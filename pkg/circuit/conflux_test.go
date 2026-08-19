package circuit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

type confluxCellSender struct {
	cells []*cell.Cell
}

func (m *confluxCellSender) SendCell(c *cell.Cell) error {
	m.cells = append(m.cells, c)
	return nil
}

func (m *confluxCellSender) ReceiveCell() (*cell.Cell, error) {
	return nil, fmt.Errorf("test sender has no receive")
}

func newOpenTestCircuit(id uint32, sender interface{ SendCell(*cell.Cell) error }) *Circuit {
	c := NewCircuit(id)
	_ = c.AddHop(&Hop{Fingerprint: "G"})
	_ = c.AddHop(&Hop{Fingerprint: "M"})
	_ = c.AddHop(&Hop{Fingerprint: "E"})
	c.SetConnection(sender)
	c.SetState(StateOpen)
	return c
}

const testExitHop = 2

func newTestConfluxSet(t *testing.T) (*ConfluxSet, *Circuit, *Circuit, *confluxCellSender, *confluxCellSender) {
	t.Helper()
	sa, sb := &confluxCellSender{}, &confluxCellSender{}
	a := newOpenTestCircuit(1, sa)
	b := newOpenTestCircuit(2, sb)
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 3)
	}
	s := &ConfluxSet{
		nonce:  nonce,
		owner:  a,
		ooo:    make(map[uint64]*cell.RelayCell),
		logger: logger.NewDefault(),
	}
	s.legs[0] = &confluxLeg{circ: a, linkedCh: make(chan struct{}, 1), linkSent: time.Now()}
	s.legs[1] = &confluxLeg{circ: b, linkedCh: make(chan struct{}, 1), linkSent: time.Now()}
	a.attachConflux(s)
	b.attachConflux(s)
	return s, a, b, sa, sb
}

func TestConfluxLinkedFalseUntilHandshake(t *testing.T) {
	c := NewCircuit(1)
	if c.ConfluxLinked() {
		t.Fatal("bare circuit must not be marked Conflux")
	}
	if c.ConfluxInfo().Linked {
		t.Fatal("ConfluxInfo.Linked must be false")
	}
}

func TestLinkConfluxRequiresFlowCtrlAndHops(t *testing.T) {
	a := NewCircuit(1)
	b := NewCircuit(2)
	a.SetState(StateOpen)
	b.SetState(StateOpen)
	if _, err := LinkConflux(context.Background(), a, b, time.Second, logger.NewDefault()); err == nil {
		t.Fatal("must require FlowCtrl=2")
	}
	a.EnableCongestionControl(31)
	b.EnableCongestionControl(31)
	if _, err := LinkConflux(context.Background(), a, b, time.Second, logger.NewDefault()); err == nil {
		t.Fatal("must require 3 hops")
	}
	if _, err := LinkConflux(context.Background(), a, a, time.Second, nil); err == nil {
		t.Fatal("must reject identical circuits")
	}
}

func TestHandleLinkedNonceAndAck(t *testing.T) {
	s, a, _, sa, _ := newTestConfluxSet(t)
	payload, err := cell.EncodeConfluxLink(&cell.ConfluxLink{
		Version:   cell.ConfluxLinkVersion,
		Nonce:     s.nonce,
		DesiredUX: cell.ConfluxUXHighThroughput,
	})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(0, cell.RelayConfluxLinked, payload)
	if err != nil {
		t.Fatal(err)
	}
	handled, err := s.onRelayCell(a, rc, testExitHop)
	if err != nil || !handled {
		t.Fatalf("LINKED: handled=%v err=%v", handled, err)
	}
	if !s.legs[0].gotLinked || !s.legs[0].ackSent {
		t.Fatal("leg must record LINKED and ACK")
	}
	if len(sa.cells) != 1 {
		t.Fatalf("expected LINKED_ACK, sent %d cells", len(sa.cells))
	}
	got, err := cell.DecodeRelayCell(sa.cells[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.RelayConfluxLinkedAck || got.StreamID != 0 {
		t.Fatalf("ACK cell %#v", got)
	}

	bad := s.nonce
	bad[0] ^= 0xff
	badPayload, _ := cell.EncodeConfluxLink(&cell.ConfluxLink{Version: cell.ConfluxLinkVersion, Nonce: bad})
	badRC, _ := cell.NewRelayCell(0, cell.RelayConfluxLinked, badPayload)
	if _, err := s.onRelayCell(a, badRC, testExitHop); err == nil {
		t.Fatal("mismatched nonce must fail")
	}
}

func TestConfluxReorderAndSwitch(t *testing.T) {
	s, a, b, _, _ := newTestConfluxSet(t)
	s.linked = true

	// 先在 B 上 SWITCH(1)，再收 DATA，绝对序号应为 2，先入 OOO。
	sw, err := cell.NewRelayCell(0, cell.RelayConfluxSwitch, cell.EncodeConfluxSwitch(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.onRelayCell(b, sw, testExitHop); err != nil {
		t.Fatal(err)
	}
	late, _ := cell.NewRelayCell(7, cell.RelayData, []byte("second"))
	if _, err := s.onRelayCell(b, late, testExitHop); err != nil {
		t.Fatal(err)
	}
	if s.lastRecv != 0 || len(s.ooo) != 1 {
		t.Fatalf("expected OOO seq2, lastRecv=%d ooo=%d", s.lastRecv, len(s.ooo))
	}

	first, _ := cell.NewRelayCell(7, cell.RelayData, []byte("first"))
	if _, err := s.onRelayCell(a, first, testExitHop); err != nil {
		t.Fatal(err)
	}
	if s.lastRecv != 2 || len(s.ooo) != 0 {
		t.Fatalf("expected drain to 2, lastRecv=%d ooo=%d", s.lastRecv, len(s.ooo))
	}

	got1, err := a.ReceiveRelayCellTimeout(time.Second)
	if err != nil || string(got1.Data) != "first" {
		t.Fatalf("first cell: %#v %v", got1, err)
	}
	got2, err := a.ReceiveRelayCellTimeout(time.Second)
	if err != nil || string(got2.Data) != "second" {
		t.Fatalf("second cell: %#v %v", got2, err)
	}
}

func TestConfluxSendSwitchRelativeSeq(t *testing.T) {
	s, a, b, sa, sb := newTestConfluxSet(t)
	s.linked = true
	s.current = a
	a.packageWindow = 100
	b.packageWindow = 100
	s.legs[0].rtt = 10 * time.Millisecond
	s.legs[1].rtt = 5 * time.Millisecond // LowRTT 选 B

	for i := 0; i < 10; i++ {
		rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.sendMultiplexed(rc); err != nil {
			t.Fatal(err)
		}
	}
	if s.lastSent != 10 || s.legs[1].lastSent != 10 {
		t.Fatalf("after 10 cells lastSent=%d legB=%d", s.lastSent, s.legs[1].lastSent)
	}
	// 堵 B，切回 A：SWITCH 相对序号应为 10。
	b.packageWindow = 0
	s.legs[0].rtt = 1 * time.Millisecond
	rc, _ := cell.NewRelayCell(1, cell.RelayData, []byte("y"))
	if err := s.sendMultiplexed(rc); err != nil {
		t.Fatal(err)
	}
	if len(sa.cells) < 2 {
		t.Fatalf("expected SWITCH+DATA on A, got %d", len(sa.cells))
	}
	sw, err := cell.DecodeRelayCell(sa.cells[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if sw.Command != cell.RelayConfluxSwitch {
		t.Fatalf("first cell on A should be SWITCH, got %s", cell.RelayCmdString(sw.Command))
	}
	rel, err := cell.DecodeConfluxSwitch(sw.Data)
	if err != nil || rel != 10 {
		t.Fatalf("SWITCH rel=%d err=%v, want 10", rel, err)
	}
	if s.lastSent != 11 || s.legs[0].lastSent != 11 {
		t.Fatalf("after switch lastSent=%d legA=%d", s.lastSent, s.legs[0].lastSent)
	}
	_ = sb
}

func TestConfluxWaitsWhenBothWindowsZero(t *testing.T) {
	s, a, b, _, _ := newTestConfluxSet(t)
	s.linked = true
	s.current = a
	a.packageWindow = 0
	b.packageWindow = 0
	rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.sendMultiplexed(rc) }()
	select {
	case err := <-done:
		t.Fatalf("both windows 0 must wait for SENDME, got %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	a.incrementPackageWindow()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after SENDME: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SENDME on one Conflux leg must unblock send")
	}
}

func TestConfluxRejectsNonExitHop(t *testing.T) {
	s, a, _, _, _ := newTestConfluxSet(t)
	s.linked = true
	payload, err := cell.EncodeConfluxLink(&cell.ConfluxLink{
		Version:   cell.ConfluxLinkVersion,
		Nonce:     s.nonce,
		DesiredUX: cell.ConfluxUXHighThroughput,
	})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(0, cell.RelayConfluxLinked, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.onRelayCell(a, rc, 0); err == nil {
		t.Fatal("LINKED from Guard hop must fail")
	}
	if _, err := s.onRelayCell(a, rc, 1); err == nil {
		t.Fatal("LINKED from Middle hop must fail")
	}
	sw, _ := cell.NewRelayCell(0, cell.RelayConfluxSwitch, cell.EncodeConfluxSwitch(1))
	if _, err := s.onRelayCell(a, sw, 0); err == nil {
		t.Fatal("SWITCH from Guard hop must fail")
	}
	data, _ := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if _, err := s.onRelayCell(a, data, 1); err == nil {
		t.Fatal("multiplex DATA from Middle hop must fail")
	}
}

func TestConfluxCloseTearsDownOtherLeg(t *testing.T) {
	_, a, b, _, _ := newTestConfluxSet(t)
	a.Close()
	if b.GetState() != StateClosed {
		t.Fatalf("closing one leg must close the other, got %s", b.GetState())
	}
	if a.confluxSet() != nil || b.confluxSet() != nil {
		t.Fatal("both legs must detach after teardown")
	}
}

func TestManagerCloseCircuitTearsDownConfluxPeer(t *testing.T) {
	m := NewManager()
	sa, sb := &confluxCellSender{}, &confluxCellSender{}
	a := newOpenTestCircuit(11, sa)
	b := newOpenTestCircuit(12, sb)
	m.mu.Lock()
	m.circuits[a.ID] = a
	m.circuits[b.ID] = b
	m.mu.Unlock()
	s := &ConfluxSet{owner: a, ooo: make(map[uint64]*cell.RelayCell), logger: logger.NewDefault(), linked: true}
	s.legs[0] = &confluxLeg{circ: a, linkedCh: make(chan struct{}, 1)}
	s.legs[1] = &confluxLeg{circ: b, linkedCh: make(chan struct{}, 1)}
	a.attachConflux(s)
	b.attachConflux(s)
	if err := m.CloseCircuit(a.ID); err != nil {
		t.Fatal(err)
	}
	if b.GetState() != StateClosed {
		t.Fatal("manager CloseCircuit must Close the peer Conflux leg")
	}
	if _, err := m.GetCircuit(b.ID); err == nil {
		t.Fatal("closed peer leg must be swept from the manager")
	}
}

func TestConfluxProtocolErrorUnlinksSet(t *testing.T) {
	s, a, b, _, _ := newTestConfluxSet(t)
	s.linked = true
	if _, err := s.onRelayCell(a, &cell.RelayCell{Command: cell.RelayConfluxSwitch, Data: []byte{0, 0, 0, 0}}, testExitHop); err == nil {
		t.Fatal("SWITCH rel=0 must fail")
	}
	s.failAndClose()
	if a.GetState() != StateClosed || b.GetState() != StateClosed {
		t.Fatal("protocol error must close both legs")
	}
	if a.ConfluxLinked() || b.ConfluxLinked() {
		t.Fatal("failed set must not stay linked")
	}
}

type failAfterSender struct {
	n    int
	sent int
}

func (m *failAfterSender) SendCell(*cell.Cell) error {
	m.sent++
	if m.sent > m.n {
		return fmt.Errorf("send fail")
	}
	return nil
}

func (m *failAfterSender) ReceiveCell() (*cell.Cell, error) {
	return nil, fmt.Errorf("test sender has no receive")
}

func TestConfluxDataFailAfterSwitchUpdatesCurrent(t *testing.T) {
	failB := &failAfterSender{n: 1} // SWITCH 成功，随后 DATA 失败
	okA := &confluxCellSender{}
	a := newOpenTestCircuit(1, okA)
	b := newOpenTestCircuit(2, failB)
	s := &ConfluxSet{
		owner:   a,
		ooo:     make(map[uint64]*cell.RelayCell),
		logger:  logger.NewDefault(),
		linked:  true,
		current: a,
	}
	s.legs[0] = &confluxLeg{circ: a, linkedCh: make(chan struct{}, 1), rtt: 10 * time.Millisecond, lastSent: 5}
	s.legs[1] = &confluxLeg{circ: b, linkedCh: make(chan struct{}, 1), rtt: time.Millisecond}
	s.lastSent = 5
	a.attachConflux(s)
	b.attachConflux(s)
	a.packageWindow = 100
	b.packageWindow = 100

	rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.sendMultiplexed(rc); err == nil {
		t.Fatal("DATA after SWITCH should fail")
	}
	if s.current != b && !s.closed {
		t.Fatal("after successful SWITCH, current must be the new leg before DATA failure")
	}
	if !s.closed {
		t.Fatal("DATA failure after SWITCH must tear down the set")
	}
	if a.GetState() != StateClosed || b.GetState() != StateClosed {
		t.Fatal("both legs must close after SWITCH+DATA failure")
	}
}

func TestConfluxRejectsSwitchFromRecvLeader(t *testing.T) {
	s, a, _, _, _ := newTestConfluxSet(t)
	s.linked = true
	s.legs[0].lastRecv = 4
	s.legs[1].lastRecv = 1
	s.lastRecv = 4
	sw, err := cell.NewRelayCell(0, cell.RelayConfluxSwitch, cell.EncodeConfluxSwitch(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.onRelayCell(a, sw, testExitHop); err == nil {
		t.Fatal("SWITCH from unique receive leader must fail")
	}
}

func TestConfluxRejectsOccupiedOOOSlot(t *testing.T) {
	s, a, b, _, _ := newTestConfluxSet(t)
	s.linked = true
	sw, err := cell.NewRelayCell(0, cell.RelayConfluxSwitch, cell.EncodeConfluxSwitch(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.onRelayCell(b, sw, testExitHop); err != nil {
		t.Fatal(err)
	}
	late, _ := cell.NewRelayCell(7, cell.RelayData, []byte("second"))
	if _, err := s.onRelayCell(b, late, testExitHop); err != nil {
		t.Fatal(err)
	}
	s.legs[0].lastRecv = 1
	dup, _ := cell.NewRelayCell(7, cell.RelayData, []byte("dup"))
	if _, err := s.onRelayCell(a, dup, testExitHop); err == nil {
		t.Fatal("occupied OOO slot must fail")
	}
}

func TestConfluxDestroyTearsDownPeer(t *testing.T) {
	_, a, b, sa, _ := newTestConfluxSet(t)
	mux := NewCellMux(sa, logger.NewDefault())
	a.SetMux(mux)
	mux.RegisterCircuit(a)
	destroy := cell.NewCell(a.ID, cell.CmdDestroy)
	destroy.Payload = []byte{1}
	mux.dispatch(destroy)
	if a.GetState() != StateClosed {
		t.Fatalf("DESTROY must Close the circuit, got %s", a.GetState())
	}
	if b.GetState() != StateClosed {
		t.Fatal("DESTROY on one Conflux leg must Close the other")
	}
}

func TestSingleCircuitNotMarkedConflux(t *testing.T) {
	s, a, _, _, _ := newTestConfluxSet(t)
	if a.ConfluxLinked() {
		t.Fatal("unlinked set must not report ConfluxLinked")
	}
	s.linked = true
	if !a.ConfluxLinked() {
		t.Fatal("linked set must report true")
	}
	s.closed = true
	if a.ConfluxLinked() {
		t.Fatal("closed set must not report linked")
	}
}
