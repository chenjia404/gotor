package relay

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

type exitStatsClock struct{ t time.Time }

func (c *exitStatsClock) Now() time.Time { return c.t }

func TestRoundUpKiB(t *testing.T) {
	if roundUpKiB(0) != 0 || roundUpKiB(1) != 1 || roundUpKiB(1024) != 1 || roundUpKiB(1025) != 2 {
		t.Fatalf("roundUpKiB: 0=%d 1=%d 1024=%d 1025=%d", roundUpKiB(0), roundUpKiB(1), roundUpKiB(1024), roundUpKiB(1025))
	}
}

func TestExitStatsOmitsIncompleteDay(t *testing.T) {
	clk := &exitStatsClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newExitStats(clk.Now)
	s.NoteOpened(80)
	clk.t = clk.t.Add(23 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("未满 24h 不得写 exit: %v", got)
	}
}

func TestExitStatsOmitsEmptyDay(t *testing.T) {
	clk := &exitStatsClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newExitStats(clk.Now)
	clk.t = clk.t.Add(24 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("无观测不得写 exit: %v", got)
	}
}

func TestExitStatsIgnoresPortZero(t *testing.T) {
	clk := &exitStatsClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newExitStats(clk.Now)
	s.NoteOpened(0)
	s.NoteBytes(0, 100, 100)
	clk.t = clk.t.Add(24 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("port=0（BEGIN_DIR）不得计入: %v", got)
	}
}

func TestExitStatsEmitsAfter24h(t *testing.T) {
	clk := &exitStatsClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	s := newExitStats(clk.Now)
	s.NoteOpened(80)
	s.NoteBytes(80, 1, 2048)
	s.NoteOpened(12345)
	s.NoteBytes(12345, 1024, 0)
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	if got["exit-stats-end"] != "2026-09-20 12:00:00 (86400 s)" {
		t.Fatalf("exit-stats-end: %q", got["exit-stats-end"])
	}
	if got["exit-streams-opened"] != "80=4,other=4" {
		t.Fatalf("streams: %q", got["exit-streams-opened"])
	}
	if got["exit-kibibytes-written"] != "80=1,other=1" {
		t.Fatalf("written: %q", got["exit-kibibytes-written"])
	}
	if got["exit-kibibytes-read"] != "80=2" {
		t.Fatalf("read: %q", got["exit-kibibytes-read"])
	}
}

func TestExitStatsSamePortStreamsRound4(t *testing.T) {
	clk := &exitStatsClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newExitStats(clk.Now)
	s.NoteOpened(443)
	s.NoteOpened(443)
	s.NoteOpened(443)
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	if got["exit-streams-opened"] != "443=4" {
		t.Fatalf("3 次仍取 4: %q", got["exit-streams-opened"])
	}
}

func TestStatsExitRequiresAllowExit(t *testing.T) {
	m := NewExitStreamManager(NewExitPolicy(logger.NewDefault()), logger.NewDefault())
	m.exitStats.NoteOpened(80)
	clk := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	m.exitStats.now = func() time.Time { return clk.Add(24 * time.Hour) }
	m.exitStats.periodStart = clk
	if got := m.StatsExit(); got != nil {
		t.Fatalf("非出口不得写 exit-*: %v", got)
	}
}

func TestHandleBeginNotesExitOther(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if _, ok := exitInterestingPorts[uint16(port)]; ok {
		t.Skip("监听端口恰好在 interesting 列表，无法断言 other")
	}
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
		close(done)
	}()

	p := testExitPolicyAllowLoopback(t)
	m := NewExitStreamManager(p, logger.NewDefault())
	circ := &ServerCircuit{CircuitID: 2, ctx: context.Background()}
	cc, err := newCircuitCrypto(bytes.Repeat([]byte{2}, 72))
	if err != nil {
		t.Fatal(err)
	}
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		for {
			if _, err := cell.DecodeCell(server); err != nil {
				return
			}
		}
	}()
	payload := []byte(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "\x00")
	if err := m.HandleBegin(context.Background(), circ, client, 9, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("未连上本地监听")
	}
	deadline := time.Now().Add(2 * time.Second)
	var streams, read uint64
	for time.Now().Before(deadline) {
		m.exitStats.mu.Lock()
		streams, read = m.exitStats.other.streams, m.exitStats.other.read
		m.exitStats.mu.Unlock()
		if streams == 1 && read >= 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if streams != 1 {
		t.Fatalf("成功 BEGIN 应记 other.streams=1, got %d", streams)
	}
	if read < 5 {
		t.Fatalf("远端 hello 应计入 read, got %d", read)
	}
	m.CloseAll()
}
