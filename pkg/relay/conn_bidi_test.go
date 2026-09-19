package relay

import (
	"net"
	"strings"
	"testing"
	"time"
)

type bidiClock struct {
	t time.Time
}

func (c *bidiClock) Now() time.Time { return c.t }

func TestClassifyBidi(t *testing.T) {
	if classifyBidi(0, 0) != bidiClassBelow {
		t.Fatal("空流量应为 below")
	}
	if classifyBidi(20479, 0) != bidiClassBelow {
		t.Fatal("低于 20480 应为 below")
	}
	if classifyBidi(20480, 0) != bidiClassRead {
		t.Fatal("只读达阈值应为 read")
	}
	if classifyBidi(0, 20480) != bidiClassWrite {
		t.Fatal("只写达阈值应为 write")
	}
	if classifyBidi(20000, 2000) != bidiClassRead {
		t.Fatal("读 ≥10× 写应为 read")
	}
	if classifyBidi(2000, 20000) != bidiClassWrite {
		t.Fatal("写 ≥10× 读应为 write")
	}
	if classifyBidi(20480, 20480) != bidiClassBoth {
		t.Fatal("双向都过阈值且未 10× 应为 both")
	}
}

func TestConnBiDirectOmitsIncompleteDay(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	e := h.register(false)
	h.noteRead(e, 100)
	clk.t = clk.t.Add(23 * time.Hour)
	if got := h.StatsMap(); got != nil {
		t.Fatalf("未满 24h 不得写 conn-bi-direct: %v", got)
	}
}

func TestConnBiDirectOmitsEmptyDay(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	clk.t = clk.t.Add(24 * time.Hour)
	if got := h.StatsMap(); got != nil {
		t.Fatalf("无连接观测不得写 0,0,0,0: %v", got)
	}
}

func TestConnBiDirectEmitsAfter24h(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	e := h.register(false)
	h.noteRead(e, 100)
	clk.t = clk.t.Add(24 * time.Hour)
	stats := h.StatsMap()
	line := stats["conn-bi-direct"]
	if line == "" {
		t.Fatal("满 24h 且有连接应写 conn-bi-direct")
	}
	if !strings.HasPrefix(line, "2026-09-20 12:00:00 (86400 s) ") {
		t.Fatalf("时间戳应为窗结束: %q", line)
	}
	// 第一格 100 字节 → below；其后空闲开着的连接每 10s 一格 below。
	if !strings.HasSuffix(line, " 8640,0,0,0") {
		t.Fatalf("空闲连接应记 below，得到 %q", line)
	}
	if stats["ipv6-conn-bi-direct"] != "" {
		t.Fatal("纯 IPv4 观测不得写 ipv6-conn-bi-direct")
	}
}

func TestConnBiDirectClassifiesReadWriteBoth(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	r := h.register(false)
	w := h.register(false)
	b := h.register(false)
	h.noteRead(r, 20480)
	h.noteWrite(w, 20480)
	h.noteRead(b, 20480)
	h.noteWrite(b, 20480)
	clk.t = clk.t.Add(10 * time.Second)
	_ = h.StatsMap()
	clk.t = clk.t.Add(24 * time.Hour)
	line := h.StatsMap()["conn-bi-direct"]
	if line == "" {
		t.Fatal("应写出已完成窗")
	}
	if !strings.HasSuffix(line, ",1,1,1") {
		t.Fatalf("第一格 read/write/both 各 1，得到 %q", line)
	}
}

func TestCountingConnFeedsConnBiDirect(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	c := newCountingConn(a, nil, h)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4)
		_, _ = b.Read(buf)
		close(done)
	}()
	if _, err := c.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	<-done
	_ = c.Close()
	clk.t = clk.t.Add(24 * time.Hour)
	if h.StatsMap()["conn-bi-direct"] == "" {
		t.Fatal("countingConn 关闭前的字节应进入 24h 窗")
	}
}

func TestConnBiDirectIPv6Line(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	e := h.register(true)
	h.noteRead(e, 100)
	clk.t = clk.t.Add(24 * time.Hour)
	stats := h.StatsMap()
	v4 := stats["conn-bi-direct"]
	v6 := stats["ipv6-conn-bi-direct"]
	if v4 == "" || v6 == "" {
		t.Fatalf("IPv6 连接应同时写两行: %v", stats)
	}
	if v4 != v6 {
		t.Fatalf("仅 IPv6 时两行计数应相同: %q vs %q", v4, v6)
	}
	if !strings.HasSuffix(v6, " 8640,0,0,0") {
		t.Fatalf("IPv6 below 计数: %q", v6)
	}
}

func TestConnBiDirectIPv6IsSubset(t *testing.T) {
	clk := &bidiClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	h := newConnBiDirect(clk.Now)
	h.noteRead(h.register(false), 100)
	h.noteRead(h.register(true), 100)
	clk.t = clk.t.Add(24 * time.Hour)
	stats := h.StatsMap()
	if !strings.HasSuffix(stats["conn-bi-direct"], " 17280,0,0,0") {
		t.Fatalf("IPv4+IPv6 合计 below: %q", stats["conn-bi-direct"])
	}
	if !strings.HasSuffix(stats["ipv6-conn-bi-direct"], " 8640,0,0,0") {
		t.Fatalf("IPv6 应为合计的子集: %q", stats["ipv6-conn-bi-direct"])
	}
}

func TestAddrIsIPv6(t *testing.T) {
	if addrIsIPv6(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9001}) {
		t.Fatal("IPv4 不得算 IPv6")
	}
	if addrIsIPv6(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 9001}) {
		t.Fatal("IPv4-mapped 不得算 IPv6")
	}
	if !addrIsIPv6(&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9001}) {
		t.Fatal("2001:db8::1 应算 IPv6")
	}
	if addrIsIPv6(nil) {
		t.Fatal("nil 不得算 IPv6")
	}
}
