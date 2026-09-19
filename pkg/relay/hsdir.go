package relay

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/onion"
)

const (
	maxHSDirEntries = 64
	maxHSDirBody    = 100 << 10
	hsDirTTL        = 3 * time.Hour
)

type hsDirPutStatus int

const (
	hsDirPutOK hsDirPutStatus = iota
	hsDirPutBad
	hsDirPutNotResponsible
)

type hsDirRingSnapshot struct {
	dirs        []*onion.HSDirectory
	srvCurrent  []byte
	srvPrev     []byte
	nReplicas   int
	spreadStore int
}

type hsDirEntry struct {
	body     []byte
	mod      time.Time
	revision uint64
}

// hsDirStore 按盲化公钥保存已验签的 v3 外层描述符。未宣告 HSDir=2。
type hsDirStore struct {
	mu      sync.Mutex
	byBlind map[string]*hsDirEntry
	selfID  []byte
	ring    *hsDirRingSnapshot
}

func (s *hsDirStore) setIdentity(id []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(id) != 32 {
		s.selfID = nil
		return
	}
	s.selfID = append([]byte(nil), id...)
}

func (s *hsDirStore) setRing(dirs []*onion.HSDirectory, current, prev []byte, p onion.HSDirRingParams) {
	if s == nil {
		return
	}
	p = p.WithDefaults()
	snap := &hsDirRingSnapshot{
		dirs:        dirs,
		nReplicas:   p.NReplicas,
		spreadStore: p.SpreadStore,
	}
	if len(current) == 32 {
		snap.srvCurrent = append([]byte(nil), current...)
	}
	if len(prev) == 32 {
		snap.srvPrev = append([]byte(nil), prev...)
	}
	s.mu.Lock()
	s.ring = snap
	s.mu.Unlock()
}

func (s *hsDirStore) put(body []byte) hsDirPutStatus {
	if s == nil || len(body) == 0 || len(body) > maxHSDirBody {
		return hsDirPutBad
	}
	if !strings.HasPrefix(string(body), "hs-descriptor") {
		return hsDirPutBad
	}
	blinded, revision, canonical, err := onion.VerifyHSDirOuterDescriptor(body)
	if err != nil || len(blinded) != 32 || len(canonical) == 0 {
		return hsDirPutBad
	}
	if !s.responsible(blinded) {
		return hsDirPutNotResponsible
	}
	key := hex.EncodeToString(blinded)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byBlind == nil {
		s.byBlind = make(map[string]*hsDirEntry)
	}
	s.expireLocked(now)
	if existing, ok := s.byBlind[key]; ok {
		if revision <= existing.revision {
			return hsDirPutBad
		}
	} else if len(s.byBlind) >= maxHSDirEntries {
		s.evictOldestLocked()
	}
	s.byBlind[key] = &hsDirEntry{body: canonical, mod: now, revision: revision}
	return hsDirPutOK
}

func (s *hsDirStore) responsible(blinded []byte) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	self := append([]byte(nil), s.selfID...)
	ring := s.ring
	s.mu.Unlock()
	if len(self) != 32 || ring == nil || len(ring.dirs) == 0 {
		return true
	}
	period := onion.GetTimePeriod(time.Now())
	periods := []uint64{period, period + 1}
	if period > 0 {
		periods = append(periods, period-1)
	}
	srvs := make([][]byte, 0, 3)
	if len(ring.srvCurrent) == 32 {
		srvs = append(srvs, ring.srvCurrent)
	}
	if len(ring.srvPrev) == 32 {
		srvs = append(srvs, ring.srvPrev)
	}
	if len(srvs) == 0 {
		srvs = append(srvs, onion.DisasterSRV(period, 0))
	}
	for _, p := range periods {
		for _, srv := range srvs {
			if onion.IsResponsibleHSDir(self, blinded, ring.dirs, srv, p, ring.nReplicas, ring.spreadStore) {
				return true
			}
		}
	}
	return false
}

func (s *hsDirStore) get(blinded []byte) ([]byte, time.Time, bool) {
	if s == nil || len(blinded) != 32 {
		return nil, time.Time{}, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	e, ok := s.byBlind[hex.EncodeToString(blinded)]
	if !ok {
		return nil, time.Time{}, false
	}
	return e.body, e.mod, true
}

func (s *hsDirStore) expireLocked(now time.Time) {
	if s.byBlind == nil {
		s.byBlind = make(map[string]*hsDirEntry)
		return
	}
	for k, e := range s.byBlind {
		if now.Sub(e.mod) >= hsDirTTL {
			delete(s.byBlind, k)
		}
	}
}

func (s *hsDirStore) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range s.byBlind {
		if first || e.mod.Before(oldest) {
			oldestKey = k
			oldest = e.mod
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.byBlind, oldestKey)
	}
}

// SetHSDirIdentity 注入本中继 Ed25519 身份，供哈希环责任判定。未宣告 HSDir=2。
func (d *DirCacheServer) SetHSDirIdentity(id []byte) {
	if d == nil || d.hs == nil {
		return
	}
	d.hs.setIdentity(id)
}

// SetHSDirRing 注入共识 HSDir 列表与 SRV。环就绪后 POST 只接受本节点负责的描述符。
func (d *DirCacheServer) SetHSDirRing(relays []*directory.Relay, current, prev []byte, params map[string]int) {
	if d == nil || d.hs == nil {
		return
	}
	d.hs.setRing(onion.HSDirectoriesFromRelays(relays), current, prev, onion.HSDirRingParamsFromConsensus(params))
}

func (d *DirCacheServer) serveHSPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHSDirBody+1))
	if err != nil || len(body) == 0 || len(body) > maxHSDirBody {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if d.hs == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch d.hs.put(body) {
	case hsDirPutOK:
		w.WriteHeader(http.StatusOK)
	case hsDirPutNotResponsible:
		http.NotFound(w, r)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

func (d *DirCacheServer) serveHSFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/tor/hs/3/")
	raw = strings.Trim(raw, "/")
	if raw == "" || raw == "publish" {
		http.NotFound(w, r)
		return
	}
	blinded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(blinded) != 32 {
		http.NotFound(w, r)
		return
	}
	body, mod, ok := d.hs.get(blinded)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeDirBody(w, r, body, mod, false)
}
