package circuit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

const (
	confluxOOOLimit   = 256
	confluxSendWait   = 5 * time.Second
	confluxDefaultRTT = time.Hour
)

// ConfluxSet 是两条已 LINK 的电路。未完成握手时不得把单电路标成 Conflux。
type ConfluxSet struct {
	mu       sync.Mutex
	sendMu   sync.Mutex
	nonce    [cell.ConfluxNonceLen]byte
	legs     [2]*confluxLeg
	owner    *Circuit
	linked   bool
	closed   bool
	lastSent uint64
	lastRecv uint64
	current  *Circuit
	ooo      map[uint64]*cell.RelayCell
	logger   *logger.Logger
}

type confluxLeg struct {
	circ      *Circuit
	lastSent  uint64
	lastRecv  uint64
	rtt       time.Duration
	linkSent  time.Time
	ackSent   bool
	gotLinked bool
	linkedCh  chan struct{}
}

// ConfluxInfo 供测试与日志观察，不含 nonce。
type ConfluxInfo struct {
	Linked bool
	Legs   []ConfluxLegInfo
}

// ConfluxLegInfo 描述一条腿的身份与测得 RTT。
type ConfluxLegInfo struct {
	CircuitID uint32
	GuardFP   string
	MiddleFP  string
	ExitFP    string
	RTT       time.Duration
}

// ConfluxLinked 表示本电路属于已完成握手的套。缺握手时恒为 false。
func (c *Circuit) ConfluxLinked() bool {
	s := c.confluxSet()
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.linked && !s.closed
}

// ConfluxInfo 返回套的可观察状态。未绑定返回零值。
func (c *Circuit) ConfluxInfo() ConfluxInfo {
	s := c.confluxSet()
	if s == nil {
		return ConfluxInfo{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info := ConfluxInfo{Linked: s.linked && !s.closed}
	for _, leg := range s.legs {
		if leg == nil || leg.circ == nil {
			continue
		}
		li := ConfluxLegInfo{CircuitID: leg.circ.ID, RTT: leg.rtt}
		hops := leg.circ.GetHops()
		if len(hops) > 0 {
			li.GuardFP = hops[0].Fingerprint
		}
		if len(hops) > 1 {
			li.MiddleFP = hops[1].Fingerprint
		}
		if len(hops) > 2 {
			li.ExitFP = hops[2].Fingerprint
		}
		info.Legs = append(info.Legs, li)
	}
	return info
}

func (c *Circuit) confluxSet() *ConfluxSet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conflux
}

func (c *Circuit) attachConflux(s *ConfluxSet) {
	c.mu.Lock()
	c.conflux = s
	c.mu.Unlock()
}

func (c *Circuit) detachConflux() {
	c.mu.Lock()
	c.conflux = nil
	c.mu.Unlock()
}

func (c *Circuit) hasSendRoom() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.State != StateOpen {
		return false
	}
	if c.vegas != nil {
		return c.vegas.packageWindow() > 0
	}
	return c.packageWindow > 0
}

func (c *Circuit) relayDataMaxLocal() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dest := len(c.Hops) - 1
	if dest >= 0 && c.Hops[dest].usesCGO() {
		return cell.RelayCellMaxDataV1(cell.RelayData)
	}
	return cell.PayloadLen - cell.RelayCellHeaderLen
}

// LinkConflux 在两条已 OPEN 且协商 FlowCtrl=2 的 3-hop 上做 LINK 握手。
// 失败时拆掉绑定（不关电路）；调用方按是否已发 LINK 决定是否关路。
func LinkConflux(ctx context.Context, primary, secondary *Circuit, timeout time.Duration, log *logger.Logger) (*ConfluxSet, error) {
	if primary == nil || secondary == nil {
		return nil, fmt.Errorf("conflux requires two circuits")
	}
	if primary == secondary {
		return nil, fmt.Errorf("conflux legs must be distinct circuits")
	}
	if !primary.CongestionControlEnabled() || !secondary.CongestionControlEnabled() {
		return nil, fmt.Errorf("conflux requires FlowCtrl=2 on both legs")
	}
	if primary.Length() < 3 || secondary.Length() < 3 {
		return nil, fmt.Errorf("conflux requires 3-hop legs")
	}
	if primary.GetState() != StateOpen || secondary.GetState() != StateOpen {
		return nil, fmt.Errorf("conflux legs must be open")
	}
	if log == nil {
		log = logger.NewDefault()
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	var nonce [cell.ConfluxNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("conflux nonce: %w", err)
	}

	s := &ConfluxSet{
		nonce:  nonce,
		owner:  primary,
		ooo:    make(map[uint64]*cell.RelayCell),
		logger: log.Component("conflux"),
	}
	s.legs[0] = &confluxLeg{circ: primary, linkedCh: make(chan struct{}, 1)}
	s.legs[1] = &confluxLeg{circ: secondary, linkedCh: make(chan struct{}, 1)}
	primary.attachConflux(s)
	secondary.attachConflux(s)

	linkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := s.sendLinks(); err != nil {
		s.teardown(false)
		return nil, err
	}
	if err := s.waitLinkedBoth(linkCtx); err != nil {
		s.teardown(false)
		return nil, err
	}

	s.mu.Lock()
	s.linked = true
	s.current = s.legs[0].circ
	if s.legs[1].rtt > 0 && (s.legs[0].rtt == 0 || s.legs[1].rtt < s.legs[0].rtt) {
		s.current = s.legs[1].circ
	}
	rtt0, rtt1 := s.legs[0].rtt, s.legs[1].rtt
	s.mu.Unlock()

	s.logger.Info("Conflux set linked",
		"primary", primary.ID,
		"secondary", secondary.ID,
		"rtt0_ms", rtt0.Milliseconds(),
		"rtt1_ms", rtt1.Milliseconds())
	return s, nil
}

func (s *ConfluxSet) sendLinks() error {
	payload, err := cell.EncodeConfluxLink(&cell.ConfluxLink{
		Version:   cell.ConfluxLinkVersion,
		Nonce:     s.nonce,
		DesiredUX: cell.ConfluxUXHighThroughput,
	})
	if err != nil {
		return err
	}
	for _, leg := range s.legs {
		rc, err := cell.NewRelayCell(0, cell.RelayConfluxLink, payload)
		if err != nil {
			return err
		}
		leg.linkSent = time.Now()
		if err := leg.circ.sendRelayCellLocal(rc); err != nil {
			return fmt.Errorf("send LINK on circ %d: %w", leg.circ.ID, err)
		}
		s.logger.Info("Conflux LINK sent", "circuit_id", leg.circ.ID)
	}
	return nil
}

func (s *ConfluxSet) waitLinkedBoth(ctx context.Context) error {
	for i, leg := range s.legs {
		select {
		case <-ctx.Done():
			return fmt.Errorf("conflux LINKED timeout on leg %d: %w", i, ctx.Err())
		case <-leg.circ.destroyCh:
			return fmt.Errorf("conflux leg %d destroyed during handshake", i)
		case <-leg.linkedCh:
		}
	}
	return nil
}

func (s *ConfluxSet) legOf(c *Circuit) *confluxLeg {
	for _, leg := range s.legs {
		if leg != nil && leg.circ == c {
			return leg
		}
	}
	return nil
}

func (s *ConfluxSet) onRelayCell(from *Circuit, rc *cell.RelayCell) (handled bool, err error) {
	if rc == nil {
		return false, nil
	}
	switch rc.Command {
	case cell.RelayConfluxLinked:
		return true, s.handleLinked(from, rc)
	case cell.RelayConfluxSwitch:
		return true, s.handleSwitch(from, rc)
	case cell.RelayConfluxLink, cell.RelayConfluxLinkedAck:
		return true, fmt.Errorf("unexpected %s on client circuit %d", cell.RelayCmdString(rc.Command), from.ID)
	}
	s.mu.Lock()
	linked := s.linked && !s.closed
	s.mu.Unlock()
	if linked && cell.ConfluxShouldMultiplex(rc.Command) {
		return true, s.reorder(from, rc)
	}
	return false, nil
}

func (s *ConfluxSet) handleLinked(from *Circuit, rc *cell.RelayCell) error {
	link, err := cell.DecodeConfluxLink(rc.Data)
	if err != nil {
		return fmt.Errorf("LINKED decode: %w", err)
	}
	if subtle.ConstantTimeCompare(link.Nonce[:], s.nonce[:]) != 1 {
		return fmt.Errorf("LINKED nonce mismatch")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("conflux set closed")
	}
	leg := s.legOf(from)
	if leg == nil {
		s.mu.Unlock()
		return fmt.Errorf("LINKED on unknown circuit")
	}
	if leg.gotLinked {
		s.mu.Unlock()
		return fmt.Errorf("duplicate LINKED on circuit %d", from.ID)
	}
	leg.gotLinked = true
	if !leg.linkSent.IsZero() {
		leg.rtt = time.Since(leg.linkSent)
	}
	rtt := leg.rtt
	s.mu.Unlock()

	ack, err := cell.NewRelayCell(0, cell.RelayConfluxLinkedAck, nil)
	if err != nil {
		return err
	}
	if err := from.sendRelayCellLocal(ack); err != nil {
		return fmt.Errorf("LINKED_ACK: %w", err)
	}

	s.mu.Lock()
	leg.ackSent = true
	s.mu.Unlock()

	s.logger.Info("Conflux LINKED",
		"circuit_id", from.ID,
		"rtt_ms", rtt.Milliseconds())
	select {
	case leg.linkedCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *ConfluxSet) handleSwitch(from *Circuit, rc *cell.RelayCell) error {
	rel, err := cell.DecodeConfluxSwitch(rc.Data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("conflux set closed")
	}
	leg := s.legOf(from)
	if leg == nil {
		return fmt.Errorf("SWITCH on unknown circuit")
	}
	leg.lastRecv += uint64(rel)
	return nil
}

func (s *ConfluxSet) reorder(from *Circuit, rc *cell.RelayCell) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("conflux set closed")
	}
	leg := s.legOf(from)
	if leg == nil {
		s.mu.Unlock()
		return fmt.Errorf("cell on unknown conflux circuit")
	}
	leg.lastRecv++
	seq := leg.lastRecv
	if seq <= s.lastRecv {
		s.mu.Unlock()
		return fmt.Errorf("conflux duplicate or old seq %d", seq)
	}
	if seq == s.lastRecv+1 {
		deliver := []*cell.RelayCell{rc}
		s.lastRecv = seq
		for {
			next, ok := s.ooo[s.lastRecv+1]
			if !ok {
				break
			}
			delete(s.ooo, s.lastRecv+1)
			s.lastRecv++
			deliver = append(deliver, next)
		}
		owner := s.owner
		s.mu.Unlock()
		for _, d := range deliver {
			if err := owner.enqueueRelayCell(d); err != nil {
				return err
			}
		}
		return nil
	}
	if len(s.ooo) >= confluxOOOLimit {
		s.mu.Unlock()
		return fmt.Errorf("conflux OOO queue exceeded %d", confluxOOOLimit)
	}
	if seq > s.lastRecv+uint64(confluxOOOLimit)+1 {
		s.mu.Unlock()
		return fmt.Errorf("conflux seq gap too large")
	}
	s.ooo[seq] = rc
	s.mu.Unlock()
	return nil
}

func (s *ConfluxSet) sendMultiplexed(rc *cell.RelayCell) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	deadline := time.Now().Add(confluxSendWait)
	var chosen *confluxLeg
	for {
		s.mu.Lock()
		if s.closed || !s.linked {
			s.mu.Unlock()
			return fmt.Errorf("conflux set not linked")
		}
		chosen = s.pickLowRTTLocked()
		s.mu.Unlock()
		if chosen != nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("both conflux legs congested")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.mu.Lock()
	needSwitch := s.current != nil && s.current != chosen.circ
	var rel uint32
	if needSwitch {
		gap := s.lastSent - chosen.lastSent
		if gap > uint64(^uint32(0)) {
			s.mu.Unlock()
			return fmt.Errorf("conflux SWITCH relative seq overflows 32 bits")
		}
		rel = uint32(gap)
	}
	circ := chosen.circ
	s.mu.Unlock()

	if needSwitch {
		sw, err := cell.NewRelayCell(0, cell.RelayConfluxSwitch, cell.EncodeConfluxSwitch(rel))
		if err != nil {
			return err
		}
		if err := circ.sendRelayCellLocal(sw); err != nil {
			return fmt.Errorf("SWITCH: %w", err)
		}
	}
	if err := circ.sendRelayCellLocal(rc); err != nil {
		return err
	}
	s.mu.Lock()
	s.current = circ
	s.lastSent++
	if leg := s.legOf(circ); leg != nil {
		leg.lastSent = s.lastSent
	}
	s.mu.Unlock()
	return nil
}

func (s *ConfluxSet) pickLowRTTLocked() *confluxLeg {
	var best *confluxLeg
	var bestRTT time.Duration
	for _, leg := range s.legs {
		if leg == nil || leg.circ == nil || !leg.circ.hasSendRoom() {
			continue
		}
		rtt := s.legRTT(leg)
		if best == nil || rtt < bestRTT {
			best = leg
			bestRTT = rtt
		}
	}
	return best
}

func (s *ConfluxSet) legRTT(leg *confluxLeg) time.Duration {
	snap := leg.circ.VegasStats()
	if snap.EWMA > 0 {
		return snap.EWMA
	}
	if snap.MinRTT > 0 {
		return snap.MinRTT
	}
	if leg.rtt > 0 {
		return leg.rtt
	}
	return confluxDefaultRTT
}

func (s *ConfluxSet) relayDataMax() int {
	max := cell.PayloadLen
	for _, leg := range s.legs {
		if leg == nil || leg.circ == nil {
			continue
		}
		if m := leg.circ.relayDataMaxLocal(); m < max {
			max = m
		}
	}
	return max
}

func (s *ConfluxSet) onLegClosed(c *Circuit) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.linked = false
	var others []*Circuit
	for _, leg := range s.legs {
		if leg != nil && leg.circ != nil && leg.circ != c {
			others = append(others, leg.circ)
		}
	}
	s.mu.Unlock()
	for _, o := range others {
		o.detachConflux()
		o.Close()
	}
}

func (s *ConfluxSet) teardown(closeLegs bool) {
	s.mu.Lock()
	s.closed = true
	s.linked = false
	var legs []*Circuit
	for _, leg := range s.legs {
		if leg != nil && leg.circ != nil {
			legs = append(legs, leg.circ)
		}
	}
	s.mu.Unlock()
	for _, c := range legs {
		c.detachConflux()
		if closeLegs {
			c.Close()
		}
	}
}
