package circuit

import (
	"bytes"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

func TestNCountEWMAMatchesProposal(t *testing.T) {
	// (curr*2 + prev*(N-1)) / (N+1)
	if got := nCountEWMA(300, 0, 2); got != 200 {
		t.Fatalf("first sample N=2: got %d want 200", got)
	}
	if got := nCountEWMA(100, 200, 2); got != 133 {
		t.Fatalf("second sample: got %d want 133", got)
	}
	if got := nCountEWMA(50, 100, 4); got != 80 {
		t.Fatalf("N=4: got %d want 80", got)
	}
}

func TestRFC3742SSInc(t *testing.T) {
	s := newVegasState(DefaultCCParams(), 31)
	s.cwnd = 124
	if inc := s.rfc3742SSInc(); inc != 31 {
		t.Fatalf("below cap pct=100: inc=%d want 31", inc)
	}
	s.cwnd = 601
	inc := s.rfc3742SSInc()
	// (31*600 + 601) / (2*601) = 19201/1202 = 15
	if inc != 15 {
		t.Fatalf("above cap: inc=%d want 15", inc)
	}
	s.cwnd = 20000
	if inc := s.rfc3742SSInc(); inc < 1 {
		t.Fatal("inc must be at least 1")
	}
}

func TestSendmePerCwndAndUpdateRate(t *testing.T) {
	if got := sendmePerCwnd(124, 31); got != 4 {
		t.Fatalf("SENDME_PER_CWND(124)=%d want 4", got)
	}
	if got := cwndUpdateRate(124, 31, 31, true); got != 1 {
		t.Fatalf("SS update rate=%d want 1", got)
	}
	// C Tor 整数除法：小 cwnd 时 UPDATE_RATE 可为 0，于是每条 SENDME 都更新。
	if got := cwndUpdateRate(186, 31, 31, false); got != 0 {
		t.Fatalf("CA update rate(186)=%d want 0", got)
	}
	if got := cwndUpdateRate(961, 31, 31, false); got != 1 {
		t.Fatalf("CA update rate(961)=%d want 1", got)
	}
}

func TestVegasSlowStartGrowsWhenFullAndLowQueue(t *testing.T) {
	c := NewCircuit(1)
	c.EnableCongestionControl(31)
	if c.packageWindow != 124 {
		t.Fatalf("initial cwnd=%d want 124", c.packageWindow)
	}
	sendAndAck(t, c, 31, 10*time.Millisecond)
	snap := c.VegasStats()
	if !snap.InSlowStart {
		t.Fatal("queue_use=0 应留在 slow start")
	}
	if snap.Cwnd <= 124 {
		t.Fatalf("full + queue_use<gamma 应指数增长, cwnd=%d", snap.Cwnd)
	}
}

func TestVegasExitsSlowStartOnHighQueue(t *testing.T) {
	c := NewCircuit(1)
	c.EnableCongestionControl(31)
	// 先用稳定 RTT 涨过 gamma，再突然拉高 RTT 让 BDP 塌缩。
	for i := 0; i < 4; i++ {
		sendAndAck(t, c, 31, 10*time.Millisecond)
	}
	if !c.VegasStats().InSlowStart {
		t.Fatal("稳定 RTT 下不应提前退出 SS")
	}
	sendAndAck(t, c, 31, 2*time.Second)
	snap := c.VegasStats()
	if snap.InSlowStart {
		t.Fatalf("queue_use>=gamma 必须退出 slow start: %+v", snap)
	}
	if snap.Cwnd < 1 {
		t.Fatalf("退出 SS 后 cwnd 非法: %+v", snap)
	}
}

func TestVegasCongestionAvoidanceDeltaAndAlpha(t *testing.T) {
	p := DefaultCCParams()
	s := newVegasState(p, 31)
	s.inSlowStart = false
	s.cwnd = 400
	s.inflight = 400
	s.cwndFull = true
	s.bdp = 50

	s.congestionAvoidance(p.VegasDelta + 10)
	want := 50 + p.VegasDelta - p.CwndInc
	if s.cwnd != want {
		t.Fatalf("delta: cwnd=%d want %d", s.cwnd, want)
	}

	s.cwnd = 400
	s.bdp = 300
	s.cwndFull = true
	s.congestionAvoidance(p.VegasBeta + 1)
	if s.cwnd != 399 {
		t.Fatalf("beta: cwnd=%d want 399", s.cwnd)
	}

	s.cwnd = 400
	s.cwndFull = true
	s.congestionAvoidance(0)
	if s.cwnd != 401 {
		t.Fatalf("alpha + full: cwnd=%d want 401", s.cwnd)
	}

	s.cwnd = 400
	s.cwndFull = false
	s.congestionAvoidance(0)
	if s.cwnd != 400 {
		t.Fatalf("alpha 但 cwnd 未满不得增加: cwnd=%d", s.cwnd)
	}

	s.cwnd = 10
	s.congestionAvoidance(p.VegasBeta + 1)
	if s.cwnd != p.CwndMin {
		t.Fatalf("不得低于 cwnd_min: cwnd=%d", s.cwnd)
	}
}

func TestVegasClockStallSkipsUpdate(t *testing.T) {
	s := newVegasState(DefaultCCParams(), 31)
	s.inflight = 31
	s.cwnd = 124
	before := s.cwnd
	s.processSendme(0)
	if s.cwnd != before {
		t.Fatalf("RTT=0 不得改 cwnd: %d → %d", before, s.cwnd)
	}
	if s.inflight != 0 {
		t.Fatalf("stall 仍须减 inflight: %d", s.inflight)
	}
}

func TestVegasClockJumpAfterSlowStart(t *testing.T) {
	s := newVegasState(DefaultCCParams(), 31)
	s.inSlowStart = false
	s.ewmaRTTUsec = 10_000
	s.minRTTUsec = 10_000
	s.inflight = 31
	before := s.cwnd
	s.processSendme(10_000 * 5001)
	if s.cwnd != before {
		t.Fatalf("5000x jump 不得改 cwnd")
	}
}

func TestVegasInflightAndPackageWindow(t *testing.T) {
	c := NewCircuit(1)
	c.EnableCongestionControl(31)
	for i := 0; i < 31; i++ {
		record, err := c.decrementPackageWindowForSendme()
		if err != nil {
			t.Fatal(err)
		}
		if record != (i == 30) {
			t.Fatalf("cell %d record=%v", i, record)
		}
	}
	if c.packageWindow != 124-31 {
		t.Fatalf("packageWindow=%d want 93", c.packageWindow)
	}
	c.vegas.inflight = c.vegas.cwnd
	c.packageWindow = 0
	if _, err := c.decrementPackageWindowForSendme(); err == nil {
		t.Fatal("cwnd 用尽必须拒绝发送")
	}
}

func TestVegasSendmeStillRequiresDigest(t *testing.T) {
	c := NewCircuit(1)
	c.EnableCongestionControl(31)
	tag := bytes.Repeat([]byte{0x5a}, 20)
	for i := 0; i < 31; i++ {
		if _, err := c.decrementPackageWindowForSendme(); err != nil {
			t.Fatal(err)
		}
	}
	c.maybeRecordSendmeTag(tag)
	if _, q := c.SendmeStats(); q != 1 {
		t.Fatalf("queued=%d want 1", q)
	}
	bad, err := cell.EncodeSendmeV1(bytes.Repeat([]byte{0x00}, 20))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(bad); err == nil {
		t.Fatal("Vegas 路径仍必须校验 SENDME v1 digest")
	}
	good, err := cell.EncodeSendmeV1(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(good); err != nil {
		t.Fatal(err)
	}
}

func TestSetCCParamsAppliedOnEnable(t *testing.T) {
	c := NewCircuit(1)
	p := DefaultCCParams()
	p.CwndInit = 248
	p.VegasGamma = 62
	c.SetCCParams(p)
	c.EnableCongestionControl(31)
	if c.packageWindow != 248 {
		t.Fatalf("cwnd_init from SetCCParams not applied: %d", c.packageWindow)
	}
	if c.VegasStats().SendmeInc != 31 {
		t.Fatal("sendme_inc 必须来自握手，不是共识")
	}
}

func TestEnableCongestionControlRejectsBadInc(t *testing.T) {
	c := NewCircuit(1)
	c.EnableCongestionControl(0)
	if c.CongestionControlEnabled() {
		t.Fatal("sendme_inc=0 不得启用")
	}
	c.EnableCongestionControl(251)
	if c.CongestionControlEnabled() {
		t.Fatal("sendme_inc>250 不得启用")
	}
	c.EnableCongestionControl(31)
	if !c.CongestionControlEnabled() || c.SendmeIncrement() != 31 {
		t.Fatal("合法 sendme_inc 应启用 Vegas")
	}
}

func TestPercentMaxMix(t *testing.T) {
	if got := percentMaxMix(10, 20, 100); got != 20 {
		t.Fatalf("pct=100 → max, got %d", got)
	}
	if got := percentMaxMix(10, 20, 0); got != 10 {
		t.Fatalf("pct=0 → min, got %d", got)
	}
	if got := percentMaxMix(10, 20, 50); got != 15 {
		t.Fatalf("pct=50 → mid, got %d", got)
	}
}

func TestCwndFullHeuristics(t *testing.T) {
	s := newVegasState(DefaultCCParams(), 31)
	s.cwnd = 186
	s.inflight = 186 - 4*31
	if !s.cwndBecameFull() {
		t.Fatal("inflight + gap*inc >= cwnd 应视为满")
	}
	s.inflight = 10
	if !s.cwndBecameNonfull() {
		t.Fatal("低于 25% 应立即非满")
	}
}

func TestBlockedChanIsCongestionSignal(t *testing.T) {
	p := DefaultCCParams()
	s := newVegasState(p, 31)
	s.inSlowStart = true
	s.cwnd = 200
	s.bdp = 200
	s.blockedChan = true
	s.cwndFull = true
	s.slowStart(0)
	if s.inSlowStart {
		t.Fatal("orconn_blocked 必须退出 slow start")
	}
	if s.cwnd != 200+p.VegasGamma {
		t.Fatalf("blocked SS 退出 cwnd=%d want %d", s.cwnd, 200+p.VegasGamma)
	}

	s.inSlowStart = false
	s.cwnd = 400
	s.blockedChan = true
	s.congestionAvoidance(0)
	if s.cwnd != 399 {
		t.Fatalf("blocked CA 应按 beta 减窗, cwnd=%d", s.cwnd)
	}
}

func sendAndAck(t *testing.T, c *Circuit, inc int, rtt time.Duration) {
	t.Helper()
	tag := bytes.Repeat([]byte{0x11}, 20)
	for i := 0; i < inc; i++ {
		if _, err := c.decrementPackageWindowForSendme(); err != nil {
			t.Fatalf("send cell: %v (window=%d)", err, c.packageWindow)
		}
	}
	c.recordSendmeTag(tag)
	c.mu.Lock()
	if n := len(c.sendmeExpected); n > 0 {
		c.sendmeExpected[n-1].sentAt = time.Now().Add(-rtt)
	}
	c.mu.Unlock()
	payload, err := cell.EncodeSendmeV1(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(payload); err != nil {
		t.Fatal(err)
	}
}
