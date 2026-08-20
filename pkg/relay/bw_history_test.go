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
