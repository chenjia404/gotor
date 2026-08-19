package circuit

import (
	"bytes"
	"crypto/sha1"
	"testing"

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
