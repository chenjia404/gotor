package relay

import (
	"strings"
	"testing"
	"time"
)

type hidservClock struct{ t time.Time }

func (c *hidservClock) Now() time.Time { return c.t }

func TestHidservStatsNoWriteBefore24h(t *testing.T) {
	clk := &hidservClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newHidservStats(clk.Now, func() float64 { return 0.5 })
	s.NoteRendCell()
	s.NoteDirOnion(bytesRepeatHS(0x01, 32))
	if got := s.StatsMap(); got != nil {
		t.Fatalf("未满 24h 不得写 hidserv: %+v", got)
	}
}

func TestHidservStatsNoWriteEmptyWindow(t *testing.T) {
	clk := &hidservClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newHidservStats(clk.Now, func() float64 { return 0.5 })
	clk.t = clk.t.Add(24 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("无观测不得写 hidserv: %+v", got)
	}
}

func TestHidservStatsObfuscatesAfter24h(t *testing.T) {
	clk := &hidservClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newHidservStats(clk.Now, func() float64 { return 0.5 })
	s.NoteRendCell()
	s.NoteDirOnion(bytesRepeatHS(0x01, 32))
	s.NoteDirOnion(bytesRepeatHS(0x01, 32))
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	if got == nil {
		t.Fatal("满 24h 且有观测必须写 hidserv-v3-*")
	}
	if got["hidserv-v3-stats-end"] != "2026-09-20 00:00:00 (86400 s)" {
		t.Fatalf("stats-end %q", got["hidserv-v3-stats-end"])
	}
	if got["hidserv-rend-v3-relayed-cells"] != "1024 delta_f=2048 epsilon=0.30 binsize=1024" {
		t.Fatalf("rend cells %q", got["hidserv-rend-v3-relayed-cells"])
	}
	if got["hidserv-dir-v3-onions-seen"] != "8 delta_f=8 epsilon=0.30 binsize=8" {
		t.Fatalf("dir onions %q", got["hidserv-dir-v3-onions-seen"])
	}
}

func TestHidservStatsUniqueOnionsAndZeroRend(t *testing.T) {
	clk := &hidservClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	s := newHidservStats(clk.Now, func() float64 { return 0.5 })
	s.NoteDirOnion(bytesRepeatHS(0xaa, 32))
	s.NoteDirOnion(bytesRepeatHS(0xbb, 32))
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	if got["hidserv-dir-v3-onions-seen"] != "8 delta_f=8 epsilon=0.30 binsize=8" {
		t.Fatalf("2 unique → bin 8, got %q", got["hidserv-dir-v3-onions-seen"])
	}
	if got["hidserv-rend-v3-relayed-cells"] != "0 delta_f=2048 epsilon=0.30 binsize=1024" {
		t.Fatalf("无会合格应为混淆后的 0, got %q", got["hidserv-rend-v3-relayed-cells"])
	}
}

func TestHidservObfuscateCanBeNegative(t *testing.T) {
	clk := &hidservClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	seq := []float64{0.5, 0.01}
	i := 0
	s := newHidservStats(clk.Now, func() float64 {
		v := seq[i]
		i++
		return v
	})
	s.NoteRendCell()
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	onions := got["hidserv-dir-v3-onions-seen"]
	if !strings.HasPrefix(onions, "-") {
		t.Fatalf("0 onions + 大负噪声应为负数, got %q", onions)
	}
	if !strings.Contains(onions, "delta_f=8 epsilon=0.30 binsize=8") {
		t.Fatalf("须带混淆参数, got %q", onions)
	}
}

func TestHidservRoundUpBin(t *testing.T) {
	if hidservRoundUpBin(0, 1024) != 0 {
		t.Fatal("0 保持 0")
	}
	if hidservRoundUpBin(1, 1024) != 1024 {
		t.Fatal("1 向上取 1024")
	}
	if hidservRoundUpBin(1024, 1024) != 1024 {
		t.Fatal("恰为倍数保持")
	}
	if hidservRoundUpBin(1025, 1024) != 2048 {
		t.Fatal("1025 向上取 2048")
	}
}

func TestHidservNilReceiver(t *testing.T) {
	var s *HidservStats
	s.NoteRendCell()
	s.NoteDirOnion(bytesRepeatHS(0x01, 32))
	if s.StatsMap() != nil {
		t.Fatal("nil receiver")
	}
}

func TestHidservStatsNoiseStableWithinPeriod(t *testing.T) {
	clk := &hidservClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	n := 0
	s := newHidservStats(clk.Now, func() float64 {
		n++
		return 0.5
	})
	s.NoteRendCell()
	clk.t = clk.t.Add(24 * time.Hour)
	a := s.StatsMap()
	b := s.StatsMap()
	if a["hidserv-rend-v3-relayed-cells"] != b["hidserv-rend-v3-relayed-cells"] ||
		a["hidserv-dir-v3-onions-seen"] != b["hidserv-dir-v3-onions-seen"] {
		t.Fatal("同一测量窗不得重新采样 Laplace 噪声")
	}
	if n != 2 {
		t.Fatalf("混淆只应在旋转时各采样一次, calls=%d", n)
	}
}
