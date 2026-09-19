package relay

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/datadir"
)

func TestCountingConnRecordsReadWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h := NewBandwidthHistory()
	c := &countingConn{Conn: a, hist: h}
	done := make(chan struct{})
	go func() {
		_, _ = b.Write([]byte("ping"))
		_, _ = b.Read(make([]byte, 8))
		close(done)
	}()
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("read %d %v", n, err)
	}
	if _, err := c.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	<-done
	if h.curRead != 4 || h.curWrite != 4 {
		t.Fatalf("counted read=%d write=%d", h.curRead, h.curWrite)
	}
}

func TestBandwidthHistoryOmitsIncompleteInterval(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 7, 0, 0, time.UTC)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(100)
	h.AddWrite(50)
	if got := h.StatsMap(); got != nil {
		t.Fatalf("未完成格不得写 history: %+v", got)
	}
}

func TestBandwidthHistoryEmitsCompletedIntervalsOnly(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(1000)
	h.AddWrite(400)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	stats := h.StatsMap()
	if stats == nil {
		t.Fatal("完成一格后应有 history")
	}
	read := stats["read-history"]
	write := stats["write-history"]
	if !strings.Contains(read, "2026-08-20 12:15:00 (900 s) 1000") {
		t.Fatalf("read-history %q", read)
	}
	if !strings.Contains(write, "2026-08-20 12:15:00 (900 s) 400") {
		t.Fatalf("write-history %q", write)
	}
	if strings.Contains(read, "1001") || strings.Contains(write, "401") {
		t.Fatal("当前未完成格不得写入")
	}
}

func TestBandwidthHistoryTwoContiguousIntervals(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(10)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	_ = h.StatsMap()
	h.AddRead(20)
	now = start.Add(30 * time.Minute)
	h.now = func() time.Time { return now }
	stats := h.StatsMap()
	if stats["read-history"] != "2026-08-20 12:30:00 (900 s) 10,20" {
		t.Fatalf("contiguous %q", stats["read-history"])
	}
}

func TestBandwidthHistoryDoesNotFillDowntimeZeros(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(10)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	_ = h.StatsMap()
	now = start.Add(3 * time.Hour)
	h.now = func() time.Time { return now }
	h.AddRead(2)
	stats := h.StatsMap()
	read := stats["read-history"]
	if strings.Count(read, ",") != 0 {
		t.Fatalf("停机空档不得补零格: %q", read)
	}
	if !strings.HasSuffix(read, " 10") {
		t.Fatalf("只应保留观测格: %q", read)
	}
}

func TestBandwidthHistoryStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, datadir.StateFileName)
	sf := &datadir.StateFile{}
	sf.Set("GuardDummy", "keep")
	if err := datadir.SaveState(path, sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.SetStatePath(path)
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(77)
	h.AddWrite(9)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	if err := h.Persist(); err != nil {
		t.Fatal(err)
	}

	loaded := NewBandwidthHistory()
	loaded.SetStatePath(path)
	loaded.now = func() time.Time { return now }
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	stats := loaded.StatsMap()
	if stats["read-history"] == "" || !strings.Contains(stats["read-history"], "77") {
		t.Fatalf("load %+v", stats)
	}

	again, err := datadir.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Get("GuardDummy"); !ok {
		t.Fatal("Persist 不得丢掉 state 里其它键")
	}
}

func TestBandwidthHistoryStateLastValueIsLive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, datadir.StateFileName)
	sf := &datadir.StateFile{}
	sf.Set(bwHistoryReadValues, "10,99")
	sf.Set(bwHistoryWriteValues, "4,7")
	sf.Set(bwHistoryReadEnds, "2026-08-20 12:30:00")
	sf.Set(bwHistoryWriteEnds, "2026-08-20 12:30:00")
	if err := datadir.SaveState(path, sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 20, 12, 20, 0, 0, time.UTC)
	h := NewBandwidthHistory()
	h.SetStatePath(path)
	h.now = func() time.Time { return now }
	if err := h.Load(); err != nil {
		t.Fatal(err)
	}
	stats := h.StatsMap()
	if stats["read-history"] != "2026-08-20 12:15:00 (900 s) 10" {
		t.Fatalf("未完成桶不得写入 history: %+v", stats)
	}
	if h.curRead != 99 || h.curWrite != 7 {
		t.Fatalf("live counters read=%d write=%d", h.curRead, h.curWrite)
	}

	if err := h.Persist(); err != nil {
		t.Fatal(err)
	}
	again, err := datadir.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := again.Get(bwHistoryReadValues); v != "10,99" {
		t.Fatalf("Persist 应保留未完成桶: %q", v)
	}
	if v, _ := again.Get(bwHistoryReadEnds); v != "2026-08-20 12:30:00" {
		t.Fatalf("Ends 应为当前桶结束: %q", v)
	}

	later := time.Date(2026, 8, 20, 12, 30, 0, 0, time.UTC)
	done := NewBandwidthHistory()
	done.SetStatePath(path)
	done.now = func() time.Time { return later }
	if err := done.Load(); err != nil {
		t.Fatal(err)
	}
	got := done.StatsMap()["read-history"]
	if got != "2026-08-20 12:30:00 (900 s) 10,99" {
		t.Fatalf("过了 Ends 后最后一格才完成: %q", got)
	}
}

func TestBandwidthHistoryEmptyPersistLeavesOfficialKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, datadir.StateFileName)
	sf := &datadir.StateFile{}
	sf.Set(bwHistoryReadValues, "42")
	sf.Set(bwHistoryWriteValues, "7")
	sf.Set(bwHistoryReadEnds, "2026-08-19 00:00:00")
	sf.Set(bwHistoryWriteEnds, "2026-08-19 00:00:00")
	if err := datadir.SaveState(path, sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}
	h := NewBandwidthHistory()
	h.SetStatePath(path)
	if err := h.Persist(); err != nil {
		t.Fatal(err)
	}
	again, err := datadir.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := again.Get(bwHistoryReadValues); v != "42" {
		t.Fatalf("无新观测时不得覆盖官方 BWHistory: %q", v)
	}
}

func TestORListenerSetBandwidthHistoryWiresExtender(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := NewORListener(DefaultORListenerConfig("127.0.0.1:0", keys), nil)
	if err != nil {
		t.Fatal(err)
	}
	hist := NewBandwidthHistory()
	ln.SetBandwidthHistory(hist)
	if ln.circuitHandler == nil || ln.circuitHandler.extender == nil {
		t.Fatal("listener 应有 EXTEND 处理")
	}
	if ln.circuitHandler.extender.bwHist != hist {
		t.Fatal("出站中间跳应与入站共用同一份带宽历史")
	}
}

func TestBandwidthHistoryOmitsIPv6WhenOnlyIPv4(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(1000)
	h.AddWrite(400)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	stats := h.StatsMap()
	if _, ok := stats["ipv6-read-history"]; ok {
		t.Fatal("仅 IPv4 不得写 ipv6-read-history")
	}
	if _, ok := stats["ipv6-write-history"]; ok {
		t.Fatal("仅 IPv4 不得写 ipv6-write-history")
	}
}

func TestBandwidthHistoryEmitsIPv6CompletedIntervals(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddIPv6Read(1000)
	h.AddIPv6Write(400)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	stats := h.StatsMap()
	if stats["read-history"] != "2026-08-20 12:15:00 (900 s) 1000" {
		t.Fatalf("总量 read %q", stats["read-history"])
	}
	if stats["write-history"] != "2026-08-20 12:15:00 (900 s) 400" {
		t.Fatalf("总量 write %q", stats["write-history"])
	}
	if stats["ipv6-read-history"] != "2026-08-20 12:15:00 (900 s) 1000" {
		t.Fatalf("ipv6-read-history %q", stats["ipv6-read-history"])
	}
	if stats["ipv6-write-history"] != "2026-08-20 12:15:00 (900 s) 400" {
		t.Fatalf("ipv6-write-history %q", stats["ipv6-write-history"])
	}
}

func TestBandwidthHistoryIPv6AlignsWithIPv4Slots(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(10)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	_ = h.StatsMap()
	h.AddIPv6Read(20)
	now = start.Add(30 * time.Minute)
	h.now = func() time.Time { return now }
	stats := h.StatsMap()
	if stats["read-history"] != "2026-08-20 12:30:00 (900 s) 10,20" {
		t.Fatalf("总量 %q", stats["read-history"])
	}
	if stats["ipv6-read-history"] != "2026-08-20 12:30:00 (900 s) 0,20" {
		t.Fatalf("IPv4 格应为 0: %q", stats["ipv6-read-history"])
	}
}

func TestBandwidthHistoryIPv6StateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, datadir.StateFileName)
	sf := &datadir.StateFile{}
	if err := datadir.SaveState(path, sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.SetStatePath(path)
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddIPv6Read(77)
	h.AddIPv6Write(9)
	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	if err := h.Persist(); err != nil {
		t.Fatal(err)
	}

	loaded := NewBandwidthHistory()
	loaded.SetStatePath(path)
	loaded.now = func() time.Time { return now }
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	stats := loaded.StatsMap()
	if stats["ipv6-read-history"] != "2026-08-20 12:15:00 (900 s) 77" {
		t.Fatalf("load ipv6 %+v", stats)
	}

	again, err := datadir.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := again.Get(bwHistoryIPv6ReadValues); v != "77,0" {
		t.Fatalf("state 应保留已完成格与未完成桶: %q", v)
	}
	if v, _ := again.Get(bwHistoryIPv6ReadEnds); v != "2026-08-20 12:30:00" {
		t.Fatalf("IPv6 Ends 应对齐总量: %q", v)
	}
}

func TestBandwidthHistoryOldStateWithoutIPv6Keys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, datadir.StateFileName)
	sf := &datadir.StateFile{}
	sf.Set(bwHistoryReadValues, "10,99")
	sf.Set(bwHistoryWriteValues, "4,7")
	sf.Set(bwHistoryReadEnds, "2026-08-20 12:30:00")
	sf.Set(bwHistoryWriteEnds, "2026-08-20 12:30:00")
	if err := datadir.SaveState(path, sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 20, 12, 20, 0, 0, time.UTC)
	h := NewBandwidthHistory()
	h.SetStatePath(path)
	h.now = func() time.Time { return now }
	if err := h.Load(); err != nil {
		t.Fatal(err)
	}
	stats := h.StatsMap()
	if _, ok := stats["ipv6-read-history"]; ok {
		t.Fatal("旧 state 无 IPv6 键不得编造 ipv6 history")
	}
	if h.curIPv6Read != 0 || h.curIPv6Write != 0 {
		t.Fatalf("旧 state live IPv6 应为 0: read=%d write=%d", h.curIPv6Read, h.curIPv6Write)
	}
}

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestCountingConnIPv6RecordsIPv6History(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h := NewBandwidthHistory()
	c := newCountingConn(remoteAddrConn{
		Conn:   a,
		remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9001},
	}, h, nil)
	done := make(chan struct{})
	go func() {
		_, _ = b.Write([]byte("ping"))
		_, _ = b.Read(make([]byte, 8))
		close(done)
	}()
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("read %d %v", n, err)
	}
	if _, err := c.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	<-done
	if h.curRead != 4 || h.curWrite != 4 {
		t.Fatalf("总量 read=%d write=%d", h.curRead, h.curWrite)
	}
	if h.curIPv6Read != 4 || h.curIPv6Write != 4 {
		t.Fatalf("IPv6 read=%d write=%d", h.curIPv6Read, h.curIPv6Write)
	}
}

func TestCountingConnIPv4MappedNotIPv6History(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h := NewBandwidthHistory()
	c := newCountingConn(remoteAddrConn{
		Conn:   a,
		remote: &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 9001},
	}, h, nil)
	done := make(chan struct{})
	go func() {
		_, _ = b.Write([]byte("ping"))
		close(done)
	}()
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	<-done
	if h.curRead != 4 {
		t.Fatalf("总量 %d", h.curRead)
	}
	if h.curIPv6Read != 0 {
		t.Fatalf("IPv4-mapped 不得计入 IPv6: %d", h.curIPv6Read)
	}
}

func TestORListenerSetConnBiDirectWiresExtender(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := NewORListener(DefaultORListenerConfig("127.0.0.1:0", keys), nil)
	if err != nil {
		t.Fatal(err)
	}
	bidi := NewConnBiDirect()
	ln.SetConnBiDirect(bidi)
	if ln.circuitHandler.extender.bidi != bidi {
		t.Fatal("出站中间跳应与入站共用同一份 conn-bi-direct")
	}
}

func TestBandwidthHistoryObservedBytesPerSec(t *testing.T) {
	if NewBandwidthHistory().ObservedBytesPerSec() != 0 {
		t.Fatal("无观测应为 0")
	}

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Minute)
	h := NewBandwidthHistory()
	h.now = func() time.Time { return now }
	h.resetCurrentLocked(now)
	h.AddRead(900000)
	h.AddWrite(450000)
	if h.ObservedBytesPerSec() != 0 {
		t.Fatal("未完成格不得当作 observed")
	}

	now = start.Add(15 * time.Minute)
	h.now = func() time.Time { return now }
	// min(900000/900, 450000/900) = min(1000, 500) = 500
	if got := h.ObservedBytesPerSec(); got != 500 {
		t.Fatalf("observed=%d want 500", got)
	}

	h.AddRead(90)
	h.AddWrite(9)
	if got := h.ObservedBytesPerSec(); got != 500 {
		t.Fatalf("当前未完成格不得抬高 observed: %d", got)
	}

	now = start.Add(30 * time.Minute)
	h.now = func() time.Time { return now }
	h.AddRead(1800000)
	h.AddWrite(1800000)
	now = start.Add(45 * time.Minute)
	h.now = func() time.Time { return now }
	// slots: 1000/500 then 2000/2000 → maxR=2000 maxW=2000 → 2000
	if got := h.ObservedBytesPerSec(); got != 2000 {
		t.Fatalf("应取各方向峰值再取较小: %d", got)
	}
}
