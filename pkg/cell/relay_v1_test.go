package cell

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRelayCellV1WithStream(t *testing.T) {
	rc, err := NewRelayCell(7, RelayBegin, []byte("example.com:443\x00"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeRelayCellV1(rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != PayloadLen {
		t.Fatalf("len %d", len(payload))
	}
	if !bytes.Equal(payload[:16], make([]byte, 16)) {
		t.Fatal("first 16 bytes must be reserved for CGO tag")
	}
	got, err := DecodeRelayCellV1(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != RelayBegin || got.StreamID != 7 || !bytes.Equal(got.Data, rc.Data) {
		t.Fatalf("roundtrip %#v", got)
	}
}

func TestEncodeDecodeRelayCellV1NoStream(t *testing.T) {
	rc, err := NewRelayCell(0, RelayExtend2, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeRelayCellV1(rc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRelayCellV1(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != RelayExtend2 || got.StreamID != 0 || !bytes.Equal(got.Data, rc.Data) {
		t.Fatalf("roundtrip %#v", got)
	}
}

func TestRelayCellMaxDataV1(t *testing.T) {
	if got := RelayCellMaxDataV1(RelayData); got != 488 {
		t.Fatalf("DATA max %d, want 488 (509-21)", got)
	}
	if got := RelayCellMaxDataV1(RelayExtend2); got != 490 {
		t.Fatalf("EXTEND2 max %d, want 490 (509-19)", got)
	}
	payload, err := EncodeRelayCellV1(&RelayCell{Command: RelayData, StreamID: 1, Data: make([]byte, 488)})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != PayloadLen {
		t.Fatalf("len %d", len(payload))
	}
	if _, err := EncodeRelayCellV1(&RelayCell{Command: RelayData, StreamID: 1, Data: make([]byte, 489)}); err == nil {
		t.Fatal("489-byte DATA must not fit v1")
	}
}

func TestEncodeRelayCellV1RejectsBadStreamID(t *testing.T) {
	if _, err := EncodeRelayCellV1(&RelayCell{Command: RelayData, StreamID: 0}); err == nil {
		t.Fatal("DATA requires stream_id")
	}
	if _, err := EncodeRelayCellV1(&RelayCell{Command: RelayExtend2, StreamID: 1}); err == nil {
		t.Fatal("EXTEND2 must not have stream_id")
	}
}

func TestEncodeDecodeSendmeCGOTag(t *testing.T) {
	tag := bytesRepeat(0x5a, 16)
	payload, err := EncodeSendmeV1(tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 19 {
		t.Fatalf("len %d", len(payload))
	}
	ver, got, err := DecodeSendme(payload)
	if err != nil || ver != SendmeVersion1 || !bytes.Equal(got, tag) {
		t.Fatalf("cgo sendme: %v %d %x", err, ver, got)
	}
}
