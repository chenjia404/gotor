package circuit

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

func TestMaybeRecordSendmeTagAtWindowMultiple(t *testing.T) {
	c := NewCircuit(1)
	tag := bytes.Repeat([]byte{0x42}, 20)

	for i := 0; i < 99; i++ {
		if err := c.decrementPackageWindow(); err != nil {
			t.Fatal(err)
		}
	}
	c.maybeRecordSendmeTag(tag)
	if _, queued := c.SendmeStats(); queued != 0 {
		t.Fatalf("must not record tag before window hits multiple of 100, queued=%d", queued)
	}

	if err := c.decrementPackageWindow(); err != nil {
		t.Fatal(err)
	}
	c.maybeRecordSendmeTag(tag)
	if _, queued := c.SendmeStats(); queued != 1 {
		t.Fatalf("expected 1 recorded tag after 100 DATA, queued=%d", queued)
	}
}

func TestProcessCircuitSendmeAcceptsMatchingDigest(t *testing.T) {
	c := NewCircuit(1)
	tag := bytes.Repeat([]byte{0x7a}, 20)
	for i := 0; i < 100; i++ {
		if err := c.decrementPackageWindow(); err != nil {
			t.Fatal(err)
		}
	}
	c.maybeRecordSendmeTag(tag)

	payload, err := cell.EncodeSendmeV1(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(payload); err != nil {
		t.Fatal(err)
	}
	if c.packageWindow != 1000 {
		t.Fatalf("packageWindow=%d want 1000", c.packageWindow)
	}
	if _, queued := c.SendmeStats(); queued != 0 {
		t.Fatalf("queue should be empty after matching SENDME")
	}
}

func TestProcessCircuitSendmeRejectsMismatch(t *testing.T) {
	c := NewCircuit(1)
	good := bytes.Repeat([]byte{0x01}, 20)
	bad := bytes.Repeat([]byte{0x02}, 20)
	for i := 0; i < 100; i++ {
		_ = c.decrementPackageWindow()
	}
	c.maybeRecordSendmeTag(good)

	payload, err := cell.EncodeSendmeV1(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(payload); err == nil {
		t.Fatal("mismatched digest must fail")
	}
}

func TestProcessCircuitSendmeRejectsV0(t *testing.T) {
	c := NewCircuit(1)
	if err := c.processCircuitSendme(nil); err == nil {
		t.Fatal("empty v0 SENDME must be rejected")
	}
}

func TestProcessCircuitSendmeUnexpected(t *testing.T) {
	c := NewCircuit(1)
	payload, err := cell.EncodeSendmeV1(bytes.Repeat([]byte{0x03}, 20))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(payload); err == nil {
		t.Fatal("SENDME without recorded tag must fail")
	}
}

func TestSendCircuitSendmeRequiresDigest(t *testing.T) {
	c := NewCircuit(1)
	c.SetState(StateOpen)
	if err := c.sendCircuitSendme(nil); err == nil {
		t.Fatal("SENDME without digest must fail")
	}
}

func TestMaybeRecordSendmeTagAtWindowZero(t *testing.T) {
	c := NewCircuit(1)
	tag := bytes.Repeat([]byte{0x11}, 20)
	for c.packageWindow > 0 {
		if err := c.decrementPackageWindow(); err != nil {
			t.Fatal(err)
		}
	}
	if c.packageWindow != 0 {
		t.Fatalf("packageWindow=%d want 0", c.packageWindow)
	}
	c.maybeRecordSendmeTag(tag)
	if _, queued := c.SendmeStats(); queued != 1 {
		t.Fatalf("1000th DATA (window=0) must record SENDME tag, queued=%d", queued)
	}
}

func TestDecrementPackageWindowForSendmeIsAtomic(t *testing.T) {
	c := NewCircuit(1)
	c.packageWindow = 101
	recordA, err := c.decrementPackageWindowForSendme()
	if err != nil || !recordA {
		t.Fatalf("101→100 是边界，应记 tag: record=%v err=%v", recordA, err)
	}
	recordB, err := c.decrementPackageWindowForSendme()
	if err != nil || recordB {
		t.Fatalf("100→99 不是边界: record=%v err=%v", recordB, err)
	}
}

func TestDecrementDeliverWindowAndTakeSendmeOnce(t *testing.T) {
	c := NewCircuit(1)
	for i := 0; i < 99; i++ {
		send, err := c.decrementDeliverWindowAndTakeSendme()
		if err != nil || send {
			t.Fatalf("cell %d: send=%v err=%v", i+1, send, err)
		}
	}
	send, err := c.decrementDeliverWindowAndTakeSendme()
	if err != nil || !send {
		t.Fatalf("100th DATA must take SENDME: send=%v err=%v", send, err)
	}
	send, err = c.decrementDeliverWindowAndTakeSendme()
	if err != nil || send {
		t.Fatalf("101st DATA must not send another SENDME: send=%v err=%v", send, err)
	}
}

func TestSendmeTagIsFullSHA1(t *testing.T) {
	h := sha1.New()
	_, _ = h.Write([]byte("cell-payload-with-zero-digest"))
	sum := h.Sum(nil)
	if len(sum) != cell.SendmeV1DigestLen {
		t.Fatalf("SHA-1 must be 20 bytes, got %d", len(sum))
	}
	payload, err := cell.EncodeSendmeV1(sum)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := cell.DecodeSendme(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, sum) {
		t.Fatal("SENDME v1 must carry the full 20-byte rolling digest, not the 4-byte cell field")
	}
}

type soakCellSender struct {
	n int
}

func (s *soakCellSender) SendCell(*cell.Cell) error {
	s.n++
	return nil
}

type soakBlockedConn struct {
	blocked bool
}

func (c soakBlockedConn) WriteBlocked() bool { return c.blocked }

func TestSendRelayCellWaitsForPackageWindow(t *testing.T) {
	c := NewCircuit(1)
	if err := c.AddHop(&Hop{Fingerprint: "E"}); err != nil {
		t.Fatal(err)
	}
	c.SetConnection(&soakCellSender{})
	c.SetState(StateOpen)
	c.packageWindow = 0

	rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- c.SendRelayCell(rc) }()

	select {
	case err := <-done:
		t.Fatalf("window=0 must wait, not return immediately: %v", err)
	case <-time.After(40 * time.Millisecond):
	}

	c.incrementPackageWindow()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after SENDME: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not wake after package window increment")
	}
}

type soakFailSender struct{}

func (soakFailSender) SendCell(*cell.Cell) error { return fmt.Errorf("send fail") }

func TestSendRelayCellRefundsWindowOnSendFail(t *testing.T) {
	c := NewCircuit(1)
	if err := c.AddHop(&Hop{Fingerprint: "E"}); err != nil {
		t.Fatal(err)
	}
	c.SetConnection(soakFailSender{})
	c.SetState(StateOpen)
	want := c.packageWindow
	rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SendRelayCell(rc); err == nil {
		t.Fatal("send must fail")
	}
	if c.packageWindow != want {
		t.Fatalf("send fail leaked window: got %d want %d", c.packageWindow, want)
	}
	if _, queued := c.SendmeStats(); queued != 0 {
		t.Fatal("unsent DATA must not enqueue a SENDME tag")
	}
}

func TestCloseWakesPackageWindowWaiter(t *testing.T) {
	c := NewCircuit(1)
	if err := c.AddHop(&Hop{Fingerprint: "E"}); err != nil {
		t.Fatal(err)
	}
	c.SetConnection(&soakCellSender{})
	c.SetState(StateOpen)
	c.packageWindow = 0
	rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.SendRelayCell(rc) }()
	time.Sleep(30 * time.Millisecond)
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close must unblock waiter with an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close must wake package-window waiter")
	}
}

type soakDeadConn struct {
	soakCellSender
}

func (soakDeadConn) IsOpen() bool { return false }

func TestWaitAbortsWhenOrconnDead(t *testing.T) {
	c := NewCircuit(1)
	if err := c.AddHop(&Hop{Fingerprint: "E"}); err != nil {
		t.Fatal(err)
	}
	c.SetConnection(soakDeadConn{})
	c.SetState(StateOpen)
	c.packageWindow = 0
	rc, err := cell.NewRelayCell(1, cell.RelayData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.SendRelayCell(rc); err == nil {
		t.Fatal("dead orconn must fail the wait")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("dead orconn must not wait the full packageWindowWait")
	}
}

func TestProcessSendmeSamplesOrconnBlocked(t *testing.T) {
	c := NewCircuit(1)
	c.SetConnection(soakBlockedConn{blocked: true})
	c.EnableCongestionControl(31)
	tag := bytes.Repeat([]byte{0x5a}, 20)
	for i := 0; i < 31; i++ {
		if _, err := c.decrementPackageWindowForSendme(); err != nil {
			t.Fatal(err)
		}
	}
	c.recordSendmeTag(tag)
	c.mu.Lock()
	if n := len(c.sendmeExpected); n > 0 {
		c.sendmeExpected[n-1].sentAt = time.Now().Add(-50 * time.Millisecond)
	}
	c.mu.Unlock()
	payload, err := cell.EncodeSendmeV1(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(payload); err != nil {
		t.Fatal(err)
	}
	snap := c.VegasStats()
	if !snap.BlockedChan {
		t.Fatal("processSendme must sample WriteBlocked into vegas.blockedChan")
	}
	if snap.InSlowStart {
		t.Fatal("orconn_blocked SENDME must exit slow start")
	}
}

func TestRecordSendmeTagTruncatesSHA3To20(t *testing.T) {
	c := NewCircuit(1)
	full := bytes.Repeat([]byte{0x5a}, 32)
	c.recordSendmeTag(full)
	if _, queued := c.SendmeStats(); queued != 1 {
		t.Fatal("SHA3-256 摘要必须入队，不能因长度 32 被丢掉")
	}
	payload, err := cell.EncodeSendmeV1(full[:cell.SendmeV1DigestLen])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.processCircuitSendme(payload); err != nil {
		t.Fatalf("对端 SENDME 携带 SHA3 前 20 字节时必须通过: %v", err)
	}
}

func TestHSRendezvousDeliverSendmeRestoresWindow(t *testing.T) {
	hop, err := NewHopFromHSKeyMaterial(bytes.Repeat([]byte{9}, 128))
	if err != nil {
		t.Fatal(err)
	}
	// 摘要认证与 CTR 无关；去掉密码层才能直接读出发出的 SENDME。
	hop.ForwardCipher = nil
	hop.BackwardCipher = nil

	c := NewCircuit(7)
	if err := c.AddHop(hop); err != nil {
		t.Fatal(err)
	}
	c.SetState(StateOpen)
	sender := &captureSendmeSender{ch: make(chan *cell.Cell, 1)}
	c.SetConnection(sender)
	c.EnableCongestionControl(1)
	before := c.deliverWindow

	relayCell, err := cell.NewRelayCell(0, cell.RelayData, []byte("onion-page"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := relayCell.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hashClone, err := crypto.CloneHash(hop.BackwardDigest)
	if err != nil {
		t.Fatal(err)
	}
	cellCopy := append([]byte(nil), payload...)
	cellCopy[5], cellCopy[6], cellCopy[7], cellCopy[8] = 0, 0, 0, 0
	if _, err := hashClone.Write(cellCopy); err != nil {
		t.Fatal(err)
	}
	full := hashClone.Sum(nil)
	if len(full) != 32 {
		t.Fatalf("会合层摘要应为 SHA3-256，got %d", len(full))
	}
	copy(payload[5:9], full[:4])

	if err := c.DeliverRelayCell(&cell.Cell{CircID: c.ID, Command: cell.CmdRelay, Payload: payload}); err != nil {
		t.Fatal(err)
	}

	select {
	case sent := <-sender.ch:
		rc, err := cell.DecodeRelayCell(sent.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if rc.Command != cell.RelaySendme {
			t.Fatalf("command=%d, want SENDME", rc.Command)
		}
		version, digest, err := cell.DecodeSendme(rc.Data)
		if err != nil {
			t.Fatal(err)
		}
		if version != cell.SendmeVersion1 {
			t.Fatalf("version=%d", version)
		}
		if !bytes.Equal(digest, full[:cell.SendmeV1DigestLen]) {
			t.Fatalf("SENDME tag=%x want SHA3 prefix %x", digest, full[:cell.SendmeV1DigestLen])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("会合末跳收到 DATA 后没有发出电路级 SENDME")
	}

	if got := c.deliverWindow; got != before {
		t.Fatalf("deliver window=%d want %d，SENDME 没有把窗口加回去", got, before)
	}
}

type captureSendmeSender struct {
	ch chan *cell.Cell
}

func (s *captureSendmeSender) SendCell(c *cell.Cell) error {
	select {
	case s.ch <- c:
	default:
	}
	return nil
}
