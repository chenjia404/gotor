package relay

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 对齐 C Tor connstats.c / dir-spec conn-bi-direct。
const (
	bidiThreshold = 20480
	bidiFactor    = 10
	bidiInterval  = 10 * time.Second
	bidiPeriod    = 24 * time.Hour
)

type bidiEntry struct {
	read  atomic.Uint64
	write atomic.Uint64
}

type bidiCompleted struct {
	end   time.Time
	nsec  int
	below uint64
	read  uint64
	write uint64
	both  uint64
}

// ConnBiDirect 按 10s 格把 OR 连接分成 below/read/write/both。
// 只在满 24h 且该窗内至少有一次分类后写入 extra-info；未完成窗不写。
type ConnBiDirect struct {
	mu          sync.Mutex
	now         func() time.Time
	periodStart time.Time
	lastSample  time.Time
	conns       map[*bidiEntry]struct{}
	below       uint64
	read        uint64
	write       uint64
	both        uint64
	completed   *bidiCompleted
}

// NewConnBiDirect 从当前时刻起算 24h 观测窗。
func NewConnBiDirect() *ConnBiDirect {
	return newConnBiDirect(func() time.Time { return time.Now().UTC() })
}

func newConnBiDirect(now func() time.Time) *ConnBiDirect {
	t := now()
	return &ConnBiDirect{
		now:         now,
		periodStart: t,
		lastSample:  t,
		conns:       make(map[*bidiEntry]struct{}),
	}
}

func (h *ConnBiDirect) register() *bidiEntry {
	if h == nil {
		return nil
	}
	e := &bidiEntry{}
	h.mu.Lock()
	h.conns[e] = struct{}{}
	h.mu.Unlock()
	return e
}

func (h *ConnBiDirect) unregister(e *bidiEntry) {
	if h == nil || e == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sampleLocked(h.now())
	if _, ok := h.conns[e]; !ok {
		return
	}
	r := e.read.Swap(0)
	w := e.write.Swap(0)
	if r > 0 || w > 0 {
		h.addClassLocked(r, w)
	}
	delete(h.conns, e)
}

func (h *ConnBiDirect) noteRead(e *bidiEntry, n uint64) {
	if h == nil || e == nil || n == 0 {
		return
	}
	e.read.Add(n)
	h.mu.Lock()
	h.sampleLocked(h.now())
	h.mu.Unlock()
}

func (h *ConnBiDirect) noteWrite(e *bidiEntry, n uint64) {
	if h == nil || e == nil || n == 0 {
		return
	}
	e.write.Add(n)
	h.mu.Lock()
	h.sampleLocked(h.now())
	h.mu.Unlock()
}

// StatsMap 只返回已完成 24h 窗的 conn-bi-direct。无观测则空。
func (h *ConnBiDirect) StatsMap() map[string]string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sampleLocked(h.now())
	if h.completed == nil {
		return nil
	}
	c := h.completed
	return map[string]string{
		"conn-bi-direct": fmt.Sprintf("%s (%d s) %d,%d,%d,%d",
			c.end.UTC().Format("2006-01-02 15:04:05"), c.nsec, c.below, c.read, c.write, c.both),
	}
}

func (h *ConnBiDirect) sampleLocked(now time.Time) {
	if h.lastSample.IsZero() {
		h.lastSample = now
		h.periodStart = now
		return
	}
	next := h.lastSample.Add(bidiInterval)
	for !next.After(now) {
		h.classifyAllLocked()
		h.lastSample = next
		if !h.lastSample.Before(h.periodStart.Add(bidiPeriod)) {
			h.finishPeriodLocked(h.lastSample)
		}
		next = h.lastSample.Add(bidiInterval)
	}
}

func (h *ConnBiDirect) classifyAllLocked() {
	for e := range h.conns {
		h.addClassLocked(e.read.Swap(0), e.write.Swap(0))
	}
}

func (h *ConnBiDirect) addClassLocked(read, write uint64) {
	switch classifyBidi(read, write) {
	case bidiClassBelow:
		h.below++
	case bidiClassRead:
		h.read++
	case bidiClassWrite:
		h.write++
	default:
		h.both++
	}
}

func (h *ConnBiDirect) finishPeriodLocked(end time.Time) {
	total := h.below + h.read + h.write + h.both
	if total > 0 {
		nsec := int(end.Sub(h.periodStart).Seconds())
		if nsec <= 0 {
			nsec = int(bidiPeriod.Seconds())
		}
		h.completed = &bidiCompleted{
			end:   end.UTC(),
			nsec:  nsec,
			below: h.below,
			read:  h.read,
			write: h.write,
			both:  h.both,
		}
	}
	h.periodStart = end
	h.below, h.read, h.write, h.both = 0, 0, 0, 0
}

type bidiClass int

const (
	bidiClassBelow bidiClass = iota
	bidiClassRead
	bidiClassWrite
	bidiClassBoth
)

func classifyBidi(read, write uint64) bidiClass {
	if read+write < bidiThreshold {
		return bidiClassBelow
	}
	if mostlyBidi(read, write) {
		return bidiClassRead
	}
	if mostlyBidi(write, read) {
		return bidiClassWrite
	}
	return bidiClassBoth
}

// mostlyBidi 为 a >= b * BIDI_FACTOR（C Tor connstats.c）。
func mostlyBidi(a, b uint64) bool {
	if b == 0 {
		return true
	}
	return a/b >= bidiFactor
}

func mergeExtraInfoStats(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		if v == "" {
			continue
		}
		dst[k] = v
	}
	return dst
}
