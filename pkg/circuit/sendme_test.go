package circuit

import (
	"bytes"
	"crypto/sha1"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
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
