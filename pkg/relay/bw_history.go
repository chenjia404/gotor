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

// Load 从 C Tor state 读入 BWHistory*。最后一格若尚未到 *Ends 则是未完成桶，不写入 extra-info。
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
	now := h.now()
	st, ok := parseBWState(sf, h.interval, now)
	if !ok {
		h.resetCurrentLocked(now)
		return nil
	}
	h.slots = st.completed
	if st.hasLive {
		h.curStart = st.curStart
		h.curRead = st.curRead
		h.curWrite = st.curWrite
	} else {
		h.resetCurrentLocked(now)
	}
	return nil
}

// Persist 按 C Tor 语义写回：已完成格 + 当前未完成桶（最后一值），*Ends 为当前桶结束时刻。
func (h *BandwidthHistory) Persist() error {
	if h == nil || h.statePath == "" {
		return nil
	}
	h.mu.Lock()
	h.rotateLocked(h.now())
	completed := append([]bwSlot(nil), h.slots...)
	curStart, curRead, curWrite := h.curStart, h.curRead, h.curWrite
	interval := h.interval
	path := h.statePath
	h.mu.Unlock()
	if len(completed) == 0 && curRead == 0 && curWrite == 0 {
		return nil
	}
	sf, err := datadir.LoadState(path)
	if err != nil {
		return err
	}
	writeSlotsToState(sf, completed, curStart, curRead, curWrite, interval)
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

type bwLoaded struct {
	completed []bwSlot
	curStart  time.Time
	curRead   uint64
	curWrite  uint64
	hasLive   bool
}

// parseBWState 按 C Tor：*Ends 是最后一桶的结束时刻；now < Ends 则最后一值是未完成桶。
func parseBWState(sf *datadir.StateFile, interval time.Duration, now time.Time) (bwLoaded, bool) {
	var empty bwLoaded
	if sf == nil {
		return empty, false
	}
	readStr, okR := sf.Get(bwHistoryReadValues)
	writeStr, okW := sf.Get(bwHistoryWriteValues)
	endStr, okE := sf.Get(bwHistoryReadEnds)
	if !okE {
		endStr, okE = sf.Get(bwHistoryWriteEnds)
	}
	if !okR || !okW || !okE {
		return empty, false
	}
	reads, ok := parseUintList(readStr)
	if !ok {
		return empty, false
	}
	writes, ok := parseUintList(writeStr)
	if !ok {
		return empty, false
	}
	end, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(endStr), time.UTC)
	if err != nil {
		return empty, false
	}
	n := len(reads)
	if len(writes) < n {
		n = len(writes)
	}
	if n == 0 {
		return empty, false
	}
	reads = reads[len(reads)-n:]
	writes = writes[len(writes)-n:]
	nsec := intervalSeconds(interval)
	dur := time.Duration(nsec) * time.Second
	live := now.Before(end)
	completedN := n
	out := bwLoaded{}
	if live {
		completedN = n - 1
		out.hasLive = true
		out.curStart = end.Add(-dur)
		out.curRead = reads[n-1]
		out.curWrite = writes[n-1]
	}
	if completedN > 0 {
		if completedN > maxBWIntervals {
			reads = reads[completedN-maxBWIntervals : completedN]
			writes = writes[completedN-maxBWIntervals : completedN]
			completedN = maxBWIntervals
		} else {
			reads = reads[:completedN]
			writes = writes[:completedN]
		}
		lastCompletedEnd := end
		if live {
			lastCompletedEnd = end.Add(-dur)
		}
		out.completed = make([]bwSlot, completedN)
		for i := 0; i < completedN; i++ {
			out.completed[i] = bwSlot{
				End:   lastCompletedEnd.Add(-time.Duration(completedN-1-i) * dur),
				Read:  reads[i],
				Write: writes[i],
			}
		}
	}
	return out, true
}

func writeSlotsToState(sf *datadir.StateFile, completed []bwSlot, curStart time.Time, curRead, curWrite uint64, interval time.Duration) {
	if sf == nil {
		return
	}
	n := len(completed) + 1
	reads := make([]string, n)
	writes := make([]string, n)
	for i, s := range completed {
		reads[i] = strconv.FormatUint(s.Read, 10)
		writes[i] = strconv.FormatUint(s.Write, 10)
	}
	reads[n-1] = strconv.FormatUint(curRead, 10)
	writes[n-1] = strconv.FormatUint(curWrite, 10)
	nsec := intervalSeconds(interval)
	end := curStart.Add(time.Duration(nsec) * time.Second).UTC().Format("2006-01-02 15:04:05")
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
