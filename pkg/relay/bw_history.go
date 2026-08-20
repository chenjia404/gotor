package relay

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/datadir"
)

// 带宽历史默认与 C Tor 一致：900 秒一格，最多保留 24 小时。
const (
	defaultBWInterval = 900 * time.Second
	maxBWIntervals    = 96
)

const (
	bwHistoryReadValues  = "BWHistoryReadValues"
	bwHistoryWriteValues = "BWHistoryWriteValues"
	bwHistoryReadEnds    = "BWHistoryReadEnds"
	bwHistoryWriteEnds   = "BWHistoryWriteEnds"
)

type bwSlot struct {
	End   time.Time
	Read  uint64
	Write uint64
}

// BandwidthHistory 记录 OR 连接上观测到的读写字节。
// 未完成的时间格不写入 extra-info；停机空档不补零（禁止编造）。
type BandwidthHistory struct {
	mu        sync.Mutex
	interval  time.Duration
	now       func() time.Time
	slots     []bwSlot
	curStart  time.Time
	curRead   uint64
	curWrite  uint64
	statePath string
}

// NewBandwidthHistory 从当前对齐的 900s 格开始累计。
func NewBandwidthHistory() *BandwidthHistory {
	h := &BandwidthHistory{
		interval: defaultBWInterval,
		now:      func() time.Time { return time.Now().UTC() },
	}
	h.resetCurrentLocked(h.now())
	return h
}

// SetStatePath 指定 DataDirectory/state，读写官方 BWHistory* 键。
func (h *BandwidthHistory) SetStatePath(path string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.statePath = path
	h.mu.Unlock()
}

// Load 从 C Tor state 读入已完成格。官方二进制留下的观测可接着用。
func (h *BandwidthHistory) Load() error {
	if h == nil || h.statePath == "" {
		return nil
	}
	sf, err := datadir.LoadState(h.statePath)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	slots, ok := slotsFromState(sf, h.interval)
	if ok {
		h.slots = slots
	}
	h.resetCurrentLocked(h.now())
	return nil
}

// Persist 把已完成格写回 state，保留 Guard 等其它键。无观测则不改 BWHistory*。
func (h *BandwidthHistory) Persist() error {
	if h == nil || h.statePath == "" {
		return nil
	}
	h.mu.Lock()
	h.rotateLocked(h.now())
	slots := append([]bwSlot(nil), h.slots...)
	path := h.statePath
	h.mu.Unlock()
	if len(slots) == 0 {
		return nil
	}
	sf, err := datadir.LoadState(path)
	if err != nil {
		return err
	}
	writeSlotsToState(sf, slots)
	return datadir.SaveState(path, sf, "Tor 0.4.9.11 (gotor)")
}

// AddRead 计入观测到的入站字节。
func (h *BandwidthHistory) AddRead(n uint64) {
	if h == nil || n == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateLocked(h.now())
	h.curRead += n
}

// AddWrite 计入观测到的出站字节。
func (h *BandwidthHistory) AddWrite(n uint64) {
	if h == nil || n == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateLocked(h.now())
	h.curWrite += n
}

// StatsMap 只返回已完成格的 write-history / read-history。无观测则空 map。
func (h *BandwidthHistory) StatsMap() map[string]string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateLocked(h.now())
	if len(h.slots) == 0 {
		return nil
	}
	nsec := int(h.interval.Seconds())
	if nsec <= 0 {
		nsec = 900
	}
	end := h.slots[len(h.slots)-1].End
	reads := make([]uint64, len(h.slots))
	writes := make([]uint64, len(h.slots))
	for i, s := range h.slots {
		reads[i] = s.Read
		writes[i] = s.Write
	}
	return map[string]string{
		"write-history": formatHistoryValue(end, nsec, writes),
		"read-history":  formatHistoryValue(end, nsec, reads),
	}
}

func (h *BandwidthHistory) resetCurrentLocked(now time.Time) {
	nsec := intervalSeconds(h.interval)
	unix := now.Unix()
	h.curStart = time.Unix((unix/nsec)*nsec, 0).UTC()
	h.curRead = 0
	h.curWrite = 0
}

func (h *BandwidthHistory) rotateLocked(now time.Time) {
	nsec := intervalSeconds(h.interval)
	dur := time.Duration(nsec) * time.Second
	curEnd := h.curStart.Add(dur)
	if now.Before(curEnd) {
		return
	}
	if h.curRead > 0 || h.curWrite > 0 {
		h.appendSlotLocked(bwSlot{End: curEnd, Read: h.curRead, Write: h.curWrite})
	}
	// 空档不补零；当前格对齐到 now。无流量的过期格直接丢弃。
	h.resetCurrentLocked(now)
}

func (h *BandwidthHistory) appendSlotLocked(s bwSlot) {
	if n := len(h.slots); n > 0 {
		expect := h.slots[n-1].End.Add(time.Duration(intervalSeconds(h.interval)) * time.Second)
		if !s.End.Equal(expect) {
			h.slots = h.slots[:0]
		}
	}
	h.slots = append(h.slots, s)
	if len(h.slots) > maxBWIntervals {
		h.slots = append([]bwSlot(nil), h.slots[len(h.slots)-maxBWIntervals:]...)
	}
}

func intervalSeconds(d time.Duration) int64 {
	nsec := int64(d.Seconds())
	if nsec <= 0 {
		return 900
	}
	return nsec
}

func formatHistoryValue(end time.Time, nsec int, values []uint64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d s) ", end.UTC().Format("2006-01-02 15:04:05"), nsec)
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", v)
	}
	return b.String()
}

func slotsFromState(sf *datadir.StateFile, interval time.Duration) ([]bwSlot, bool) {
	if sf == nil {
		return nil, false
	}
	readStr, okR := sf.Get(bwHistoryReadValues)
	writeStr, okW := sf.Get(bwHistoryWriteValues)
	endStr, okE := sf.Get(bwHistoryReadEnds)
	if !okE {
		endStr, okE = sf.Get(bwHistoryWriteEnds)
	}
	if !okR || !okW || !okE {
		return nil, false
	}
	reads, ok := parseUintList(readStr)
	if !ok {
		return nil, false
	}
	writes, ok := parseUintList(writeStr)
	if !ok {
		return nil, false
	}
	end, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(endStr), time.UTC)
	if err != nil {
		return nil, false
	}
	n := len(reads)
	if len(writes) < n {
		n = len(writes)
	}
	if n == 0 {
		return nil, false
	}
	reads = reads[len(reads)-n:]
	writes = writes[len(writes)-n:]
	nsec := intervalSeconds(interval)
	slots := make([]bwSlot, n)
	for i := 0; i < n; i++ {
		slots[i] = bwSlot{
			End:   end.Add(-time.Duration(n-1-i) * time.Duration(nsec) * time.Second),
			Read:  reads[i],
			Write: writes[i],
		}
	}
	if len(slots) > maxBWIntervals {
		slots = slots[len(slots)-maxBWIntervals:]
	}
	return slots, true
}

func writeSlotsToState(sf *datadir.StateFile, slots []bwSlot) {
	if sf == nil || len(slots) == 0 {
		return
	}
	reads := make([]string, len(slots))
	writes := make([]string, len(slots))
	for i, s := range slots {
		reads[i] = strconv.FormatUint(s.Read, 10)
		writes[i] = strconv.FormatUint(s.Write, 10)
	}
	end := slots[len(slots)-1].End.UTC().Format("2006-01-02 15:04:05")
	sf.Set(bwHistoryReadValues, strings.Join(reads, ","))
	sf.Set(bwHistoryWriteValues, strings.Join(writes, ","))
	sf.Set(bwHistoryReadEnds, end)
	sf.Set(bwHistoryWriteEnds, end)
}

func parseUintList(s string) ([]uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ",")
	out := make([]uint64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
