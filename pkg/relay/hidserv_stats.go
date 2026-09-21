package relay

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/security"
)

const hidservPeriod = 24 * time.Hour

// dir-spec extra-info hidserv-* / proposal 238 默认混淆参数。
const (
	hidservRendDeltaF  = 2048
	hidservRendEpsilon = 0.30
	hidservRendBin     = 1024
	hidservDirDeltaF   = 8
	hidservDirEpsilon  = 0.30
	hidservDirBin      = 8
)

type hidservCompleted struct {
	end      time.Time
	nsec     int
	rendObf  int64
	onionObf int64
}

// HidservStats 统计会合点转发的 RELAY 格与 HSDir 接受的唯一盲化公钥。
// 满 24h 且该窗有观测才写入 extra-info hidserv-v3-*；按规范先向上取 bin 再加 Laplace 噪声。
// 只写 v3（本实现无 v2 洋葱）；不宣告 HS* proto。
type HidservStats struct {
	mu          sync.Mutex
	now         func() time.Time
	rand        func() float64 // Uniform (0,1)
	periodStart time.Time
	rendCells   uint64
	onions      map[string]struct{}
	completed   *hidservCompleted
}

func NewHidservStats() *HidservStats {
	return newHidservStats(func() time.Time { return time.Now().UTC() }, hidservRandUnit)
}

func newHidservStats(now func() time.Time, rnd func() float64) *HidservStats {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if rnd == nil {
		rnd = hidservRandUnit
	}
	return &HidservStats{now: now, rand: rnd, periodStart: now()}
}

// NoteRendCell 在会合点成功处理 RENDEZVOUS1 之后，每转发一格 RELAY 计一次。
func (s *HidservStats) NoteRendCell() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	s.rendCells++
}

// NoteDirOnion 计入一次被本 HSDir 接受的盲化公钥（24h 窗内 unique）。
func (s *HidservStats) NoteDirOnion(blinded []byte) {
	if s == nil || len(blinded) != 32 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	if s.onions == nil {
		s.onions = make(map[string]struct{})
	}
	s.onions[string(blinded)] = struct{}{}
}

// StatsMap 返回已完成窗的 hidserv-v3-stats-end / rend-v3-relayed-cells / dir-v3-onions-seen。无观测则空。
func (s *HidservStats) StatsMap() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	if s.completed == nil {
		return nil
	}
	c := s.completed
	return map[string]string{
		"hidserv-v3-stats-end": fmt.Sprintf("%s (%d s)",
			c.end.UTC().Format("2006-01-02 15:04:05"), c.nsec),
		"hidserv-rend-v3-relayed-cells": fmt.Sprintf("%d delta_f=%d epsilon=%.2f binsize=%d",
			c.rendObf, hidservRendDeltaF, hidservRendEpsilon, hidservRendBin),
		"hidserv-dir-v3-onions-seen": fmt.Sprintf("%d delta_f=%d epsilon=%.2f binsize=%d",
			c.onionObf, hidservDirDeltaF, hidservDirEpsilon, hidservDirBin),
	}
}

func (s *HidservStats) rotateLocked(now time.Time) {
	end := s.periodStart.Add(hidservPeriod)
	if now.Before(end) {
		return
	}
	if s.hasCountsLocked() {
		nsec := int(end.Sub(s.periodStart).Seconds())
		if nsec <= 0 {
			nsec = int(hidservPeriod.Seconds())
		}
		s.completed = &hidservCompleted{
			end:      end.UTC(),
			nsec:     nsec,
			rendObf:  hidservObfuscate(s.rendCells, hidservRendDeltaF, hidservRendEpsilon, hidservRendBin, s.rand()),
			onionObf: hidservObfuscate(uint64(len(s.onions)), hidservDirDeltaF, hidservDirEpsilon, hidservDirBin, s.rand()),
		}
	}
	unix := now.Unix()
	nsec := int64(hidservPeriod.Seconds())
	s.periodStart = time.Unix((unix/nsec)*nsec, 0).UTC()
	if !s.periodStart.After(end) {
		s.periodStart = end
	}
	s.rendCells = 0
	s.onions = nil
}

func (s *HidservStats) hasCountsLocked() bool {
	return s.rendCells > 0 || len(s.onions) > 0
}

func hidservRoundUpBin(n, bin uint64) uint64 {
	if bin == 0 || n == 0 {
		return n
	}
	rem := n % bin
	if rem == 0 {
		return n
	}
	return n + (bin - rem)
}

func hidservLaplace(mu, b, p float64) float64 {
	if p <= 0 {
		p = math.SmallestNonzeroFloat64
	}
	if p >= 1 {
		p = 1 - 1e-16
	}
	if p < 0.5 {
		return mu + b*math.Log(2*p)
	}
	return mu - b*math.Log(2*(1-p))
}

func hidservObfuscate(n uint64, deltaF, epsilon float64, bin uint64, u float64) int64 {
	if epsilon <= 0 {
		return security.Uint64ToInt64Sat(hidservRoundUpBin(n, bin))
	}
	rounded := hidservRoundUpBin(n, bin)
	noise := hidservLaplace(0, deltaF/epsilon, u)
	return int64(math.Floor(float64(rounded) + noise))
}

func hidservRandUnit() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	u := float64(binary.BigEndian.Uint64(b[:])) / (1 << 64)
	if u <= 0 {
		return math.SmallestNonzeroFloat64
	}
	return u
}
