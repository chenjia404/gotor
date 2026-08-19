package circuit

import (
	"sync/atomic"
	"time"
)

// monotimeClockBroken 对应 C Tor is_monotime_clock_broken：
// 出现过 0-delta RTT 后，过小的 RTT 才被当成 stall。
var monotimeClockBroken atomic.Bool

// vegasState 是一条电路上的 TOR_VEGAS 状态。
// 对照 proposal 324 §3.3 与 C Tor congestion_control_vegas.c。
type vegasState struct {
	params        CCParams
	sendmeInc     int
	cwnd          int
	inflight      int
	inSlowStart   bool
	cwndFull      bool
	nextCCEvent   int
	nextCwndEvent int
	minRTTUsec    int64
	maxRTTUsec    int64
	ewmaRTTUsec   int64
	bdp           int
	blockedChan   bool
}

func newVegasState(p CCParams, sendmeInc int) *vegasState {
	if sendmeInc < 1 {
		sendmeInc = sendmeIncDefault
	}
	if p.CwndInit < sendmeInc {
		p.CwndInit = sendmeInc
	}
	s := &vegasState{
		params:      p,
		sendmeInc:   sendmeInc,
		cwnd:        p.CwndInit,
		inSlowStart: true,
		nextCCEvent: 1, // Slow Start 下 CWND_UPDATE_RATE = 1
	}
	return s
}

func (s *vegasState) packageWindow() int {
	if s.inflight >= s.cwnd {
		return 0
	}
	return s.cwnd - s.inflight
}

func sendmePerCwnd(cwnd, sendmeInc int) int {
	if sendmeInc < 1 {
		sendmeInc = 1
	}
	return (cwnd + sendmeInc/2) / sendmeInc
}

func cwndUpdateRate(cwnd, incRate, sendmeInc int, inSlowStart bool) int {
	if inSlowStart {
		return 1
	}
	den := incRate * sendmeInc
	if den < 1 {
		den = 1
	}
	return (cwnd + den/2) / den
}

// nCountEWMA 必须用 proposal 的重排形式，才能与 C Tor 同一套取整：
// N_EWMA = (curr*2 + prev*(N-1)) / (N+1)
func nCountEWMA(curr, prev, n int64) int64 {
	if n < 1 {
		n = 1
	}
	return (curr*2 + prev*(n-1)) / (n + 1)
}

func percentMaxMix(a, b int64, pctMax int) int64 {
	if pctMax < 0 {
		pctMax = 0
	}
	if pctMax > 100 {
		pctMax = 100
	}
	maxV, minV := a, b
	if b > a {
		maxV, minV = b, a
	}
	return (maxV*int64(pctMax) + minV*int64(100-pctMax)) / 100
}

const deltaDiscrepancyRatioMax = 5000

func timeDeltaStalledOrJumped(inSlowStart bool, ewma, newDelta int64) bool {
	if newDelta <= 0 {
		monotimeClockBroken.Store(true)
		return true
	}
	if inSlowStart || ewma == 0 {
		return false
	}
	if newDelta > ewma*deltaDiscrepancyRatioMax {
		return true
	}
	if newDelta*deltaDiscrepancyRatioMax < ewma {
		return monotimeClockBroken.Load()
	}
	monotimeClockBroken.Store(false)
	return false
}

func (s *vegasState) nEWMACount() int64 {
	var n int64
	if s.inSlowStart {
		n = int64(s.params.EwmaSS)
	} else {
		n = int64(cwndUpdateRate(s.cwnd, s.params.CwndIncRate, s.sendmeInc, false) * s.params.EwmaCwndPct / 100)
		if max := int64(s.params.EwmaMax); n > max {
			n = max
		}
	}
	if n < 2 {
		n = 2
	}
	return n
}

func (s *vegasState) rfc3742SSInc() int {
	if s.cwnd <= 0 {
		return 1
	}
	if s.cwnd <= s.params.SSCap {
		return (s.params.CwndIncPctSS*s.sendmeInc + 50) / 100
	}
	inc := (s.sendmeInc*s.params.SSCap + s.cwnd) / (2 * s.cwnd)
	if inc < 1 {
		return 1
	}
	return inc
}

func (s *vegasState) cwndBecameFull() bool {
	return s.inflight+s.params.CwndFullGap*s.sendmeInc >= s.cwnd
}

func (s *vegasState) cwndBecameNonfull() bool {
	return 100*s.inflight < s.params.CwndFullMinPct*s.cwnd
}

func (s *vegasState) cwndFullReset() bool {
	if s.params.CwndFullPerCwnd == 1 {
		return s.nextCwndEvent == sendmePerCwnd(s.cwnd, s.sendmeInc)
	}
	return s.nextCCEvent == cwndUpdateRate(s.cwnd, s.params.CwndIncRate, s.sendmeInc, s.inSlowStart)
}

func (s *vegasState) ackInflight() {
	s.inflight -= s.sendmeInc
	if s.inflight < 0 {
		s.inflight = 0
	}
}

func (s *vegasState) updateEstimates(rttUsec int64) bool {
	if timeDeltaStalledOrJumped(s.inSlowStart, s.ewmaRTTUsec, rttUsec) {
		return false
	}
	s.ewmaRTTUsec = nCountEWMA(rttUsec, s.ewmaRTTUsec, s.nEWMACount())
	if rttUsec > s.maxRTTUsec {
		s.maxRTTUsec = rttUsec
	}
	switch {
	case s.minRTTUsec == 0:
		s.minRTTUsec = s.ewmaRTTUsec
	case s.cwnd == s.params.CwndMin && !s.inSlowStart:
		s.minRTTUsec = percentMaxMix(s.ewmaRTTUsec, s.minRTTUsec, s.params.RTTResetPct)
	case s.ewmaRTTUsec < s.minRTTUsec:
		s.minRTTUsec = s.ewmaRTTUsec
	}
	if s.ewmaRTTUsec == 0 {
		s.bdp = s.cwnd
		return s.blockedChan
	}
	s.bdp = int(int64(s.cwnd) * s.minRTTUsec / s.ewmaRTTUsec)
	return true
}

func (s *vegasState) clampCwnd() {
	if s.cwnd > s.params.CwndMax {
		s.cwnd = s.params.CwndMax
	}
	if s.cwnd < 1 {
		s.cwnd = 1
	}
}

func (s *vegasState) exitSlowStart() {
	s.inSlowStart = false
}

func (s *vegasState) slowStart(queueUse int) {
	if queueUse < s.params.VegasGamma && !s.blockedChan {
		if s.cwndFull {
			inc := s.rfc3742SSInc()
			s.cwnd += inc
			if inc*sendmePerCwnd(s.cwnd, s.sendmeInc) <= s.params.CwndInc*s.params.CwndIncRate {
				s.exitSlowStart()
			}
		}
	} else {
		s.cwnd = s.bdp + s.params.VegasGamma
		s.exitSlowStart()
	}
	if s.cwnd >= s.params.SSMax {
		s.cwnd = s.params.SSMax
		s.exitSlowStart()
	}
	s.clampCwnd()
}

func (s *vegasState) congestionAvoidance(queueUse int) {
	switch {
	case queueUse > s.params.VegasDelta:
		s.cwnd = s.bdp + s.params.VegasDelta - s.params.CwndInc
	case queueUse > s.params.VegasBeta || s.blockedChan:
		s.cwnd -= s.params.CwndInc
	case s.cwndFull && queueUse < s.params.VegasAlpha:
		s.cwnd += s.params.CwndInc
	}
	if s.cwnd < s.params.CwndMin {
		s.cwnd = s.params.CwndMin
	}
	s.clampCwnd()
}

// processSendme 在校验过的电路级 SENDME 上跑一轮 Vegas。
// rttUsec<=0 视为 clock stall：不改 cwnd，只减 inflight。
func (s *vegasState) processSendme(rttUsec int64) {
	if s.nextCCEvent > 0 {
		s.nextCCEvent--
	}
	if s.nextCwndEvent > 0 {
		s.nextCwndEvent--
	}
	if !s.updateEstimates(rttUsec) {
		s.ackInflight()
		return
	}
	queueUse := 0
	if s.bdp <= s.cwnd {
		queueUse = s.cwnd - s.bdp
	}
	if s.cwndBecameFull() {
		s.cwndFull = true
	} else if s.cwndBecameNonfull() {
		s.cwndFull = false
	}
	if s.inSlowStart {
		s.slowStart(queueUse)
	} else if s.nextCCEvent == 0 {
		s.congestionAvoidance(queueUse)
	}
	if s.nextCwndEvent == 0 {
		s.nextCwndEvent = sendmePerCwnd(s.cwnd, s.sendmeInc)
	}
	if s.nextCCEvent == 0 {
		s.nextCCEvent = cwndUpdateRate(s.cwnd, s.params.CwndIncRate, s.sendmeInc, s.inSlowStart)
	}
	if s.cwndFullReset() {
		s.cwndFull = false
	}
	s.ackInflight()
}

func (s *vegasState) queueUse() int {
	if s.bdp > s.cwnd {
		return 0
	}
	return s.cwnd - s.bdp
}

// VegasSnapshot 供测试与 soak 日志观察，不是协议的一部分。
type VegasSnapshot struct {
	Enabled     bool
	InSlowStart bool
	Cwnd        int
	Inflight    int
	BDP         int
	QueueUse    int
	SendmeInc   int
	BlockedChan bool
	MinRTT      time.Duration
	EWMA        time.Duration
}

func (s *vegasState) snapshot() VegasSnapshot {
	if s == nil {
		return VegasSnapshot{}
	}
	return VegasSnapshot{
		Enabled:     true,
		InSlowStart: s.inSlowStart,
		Cwnd:        s.cwnd,
		Inflight:    s.inflight,
		BDP:         s.bdp,
		QueueUse:    s.queueUse(),
		SendmeInc:   s.sendmeInc,
		BlockedChan: s.blockedChan,
		MinRTT:      time.Duration(s.minRTTUsec) * time.Microsecond,
		EWMA:        time.Duration(s.ewmaRTTUsec) * time.Microsecond,
	}
}
