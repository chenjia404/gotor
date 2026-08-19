// Package onion — HSDir 哈希环选路（rend-spec-v3 §2.2.3 WHERE-HSDESC）。
//
// 对照 C Tor hs_build_hs_index / hs_build_hsdir_index / hs_get_responsible_hsdirs
// 与 Arti tor-netdir hsdir_ring.rs。
package onion

import (
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	hsdirNReplicasDefault   = 2
	hsdirSpreadFetchDefault = 3
	hsdirSpreadStoreDefault = 4
	hsIndexPrefix           = "store-at-idx"
	hsdirIndexPrefix        = "node-idx"
	hsSRVDisasterPrefix     = "shared-random-disaster"
)

// DisasterSRV = SHA3_256("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
func DisasterSRV(periodNum, periodLengthMinutes uint64) []byte {
	if periodLengthMinutes == 0 {
		periodLengthMinutes = hsdirIntervalDefaultMinutes
	}
	h := sha3.New256()
	_, _ = h.Write([]byte(hsSRVDisasterPrefix))
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], periodLengthMinutes)
	binary.BigEndian.PutUint64(buf[8:16], periodNum)
	_, _ = h.Write(buf[:])
	return h.Sum(nil)
}

// BuildHSIndex = SHA3_256("store-at-idx" | blinded | INT_8(replica) | INT_8(len) | INT_8(period))
// replica 从 1 起（规范 hsdir_n_replicas）。
func BuildHSIndex(blindedPubkey []byte, replica, periodNum, periodLengthMinutes uint64) ([]byte, error) {
	if len(blindedPubkey) != 32 {
		return nil, fmt.Errorf("blinded pubkey must be 32 bytes")
	}
	if replica == 0 {
		return nil, fmt.Errorf("replica must be >= 1")
	}
	if periodLengthMinutes == 0 {
		periodLengthMinutes = hsdirIntervalDefaultMinutes
	}
	h := sha3.New256()
	_, _ = h.Write([]byte(hsIndexPrefix))
	_, _ = h.Write(blindedPubkey)
	var buf [24]byte
	binary.BigEndian.PutUint64(buf[0:8], replica)
	binary.BigEndian.PutUint64(buf[8:16], periodLengthMinutes)
	binary.BigEndian.PutUint64(buf[16:24], periodNum)
	_, _ = h.Write(buf[:])
	return h.Sum(nil), nil
}

// BuildHSDirIndex = SHA3_256("node-idx" | ed25519_id | srv | INT_8(period_num) | INT_8(period_length))
// 注意：字段顺序与 C Tor / Arti 一致（period_num 在前；规范文本曾写反）。
func BuildHSDirIndex(nodeIdentity, srv []byte, periodNum, periodLengthMinutes uint64) ([]byte, error) {
	if len(nodeIdentity) != 32 {
		return nil, fmt.Errorf("node identity must be 32 bytes")
	}
	if len(srv) != 32 {
		return nil, fmt.Errorf("shared random value must be 32 bytes")
	}
	if periodLengthMinutes == 0 {
		periodLengthMinutes = hsdirIntervalDefaultMinutes
	}
	h := sha3.New256()
	_, _ = h.Write([]byte(hsdirIndexPrefix))
	_, _ = h.Write(nodeIdentity)
	_, _ = h.Write(srv)
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], periodNum)
	binary.BigEndian.PutUint64(buf[8:16], periodLengthMinutes)
	_, _ = h.Write(buf[:])
	return h.Sum(nil), nil
}

// UseCurrentSRVForFetch 客户端拉取时选用 current 还是 previous SRV。
//
// C Tor：若处于「TP 与下一 SRV 之间」（约每日 12:00–00:00 UTC）用 current，
// 否则（SRV 与下一 TP 之间，约 00:00–12:00）用 previous。
func UseCurrentSRVForFetch(now time.Time) bool {
	return now.UTC().Hour() >= 12
}

// SelectSRVForFetch 根据时刻选择 SRV；缺失时回退 disaster。
func SelectSRVForFetch(now time.Time, periodNum uint64, current, previous []byte) []byte {
	wantCurrent := UseCurrentSRVForFetch(now)
	if wantCurrent && len(current) == 32 {
		return current
	}
	if !wantCurrent && len(previous) == 32 {
		return previous
	}
	// 回退：有哪个用哪个，再不行 disaster
	if len(current) == 32 {
		return current
	}
	if len(previous) == 32 {
		return previous
	}
	return DisasterSRV(periodNum, hsdirIntervalDefaultMinutes)
}

type hsdirRingEntry struct {
	dir   *HSDirectory
	index []byte
}

// SelectResponsibleHSDirs 按哈希环选取负责目录（拉取用 spread_fetch）。
// hsdirs 中须带 Relay.IdentityKey（Ed25519）；无身份的跳过。
func SelectResponsibleHSDirs(
	blindedPubkey []byte,
	hsdirs []*HSDirectory,
	srv []byte,
	periodNum uint64,
	nReplicas, spreadFetch int,
) []*HSDirectory {
	if nReplicas <= 0 {
		nReplicas = hsdirNReplicasDefault
	}
	if spreadFetch <= 0 {
		spreadFetch = hsdirSpreadFetchDefault
	}
	periodLen := uint64(hsdirIntervalDefaultMinutes)

	ring := make([]hsdirRingEntry, 0, len(hsdirs))
	for _, d := range hsdirs {
		if d == nil || !d.HSDir {
			continue
		}
		id := d.ed25519Identity()
		if len(id) != 32 {
			continue
		}
		idx, err := BuildHSDirIndex(id, srv, periodNum, periodLen)
		if err != nil {
			continue
		}
		ring = append(ring, hsdirRingEntry{dir: d, index: idx})
	}
	if len(ring) == 0 {
		return nil
	}
	sort.Slice(ring, func(i, j int) bool {
		return compareBytes(ring[i].index, ring[j].index) < 0
	})

	seen := make(map[string]struct{})
	out := make([]*HSDirectory, 0, nReplicas*spreadFetch)
	for replica := 1; replica <= nReplicas; replica++ {
		hsIdx, err := BuildHSIndex(blindedPubkey, uint64(replica), periodNum, periodLen)
		if err != nil {
			continue
		}
		start := sort.Search(len(ring), func(i int) bool {
			return compareBytes(ring[i].index, hsIdx) >= 0
		})
		if start == len(ring) {
			start = 0
		}
		added := 0
		i := start
		for added < spreadFetch {
			d := ring[i].dir
			key := d.Fingerprint
			if key == "" {
				key = fmt.Sprintf("%s:%d", d.Address, d.ORPort)
			}
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, d)
				added++
			}
			i++
			if i == len(ring) {
				i = 0
			}
			if i == start {
				break
			}
		}
	}
	return out
}

func (d *HSDirectory) ed25519Identity() []byte {
	if d == nil || d.Relay == nil {
		return nil
	}
	id := d.Relay.IdentityKey
	if len(id) == 32 {
		return id
	}
	return nil
}
