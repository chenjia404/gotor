package cell

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeConfluxLink(t *testing.T) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	in := &ConfluxLink{
		Version:     ConfluxLinkVersion,
		Nonce:       nonce,
		LastSeqSent: 0x0102030405060708,
		LastSeqRecv: 0x1112131415161718,
		DesiredUX:   ConfluxUXHighThroughput,
	}
	raw, err := EncodeConfluxLink(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != ConfluxLinkPayloadLen {
		t.Fatalf("len %d, want %d", len(raw), ConfluxLinkPayloadLen)
	}
	if raw[0] != 0x01 || raw[49] != ConfluxUXHighThroughput {
		t.Fatalf("version/ux bytes %#x %#x", raw[0], raw[49])
	}
	// 大端：LAST_SEQNO_SENT 在 nonce 之后。
	if !bytes.Equal(raw[33:41], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) {
		t.Fatalf("sent endian %#x", raw[33:41])
	}
	if !bytes.Equal(raw[41:49], []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}) {
		t.Fatalf("recv endian %#x", raw[41:49])
	}
	out, err := DecodeConfluxLink(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != in.Version || out.LastSeqSent != in.LastSeqSent ||
		out.LastSeqRecv != in.LastSeqRecv || out.DesiredUX != in.DesiredUX ||
		!bytes.Equal(out.Nonce[:], in.Nonce[:]) {
		t.Fatalf("roundtrip %#v", out)
	}
}

func TestDecodeConfluxLinkRejects(t *testing.T) {
	if _, err := DecodeConfluxLink(make([]byte, 49)); err == nil {
		t.Fatal("short payload must fail")
	}
	raw := make([]byte, ConfluxLinkPayloadLen)
	raw[0] = 0x02
	if _, err := DecodeConfluxLink(raw); err == nil {
		t.Fatal("version 2 must fail")
	}
	if _, err := EncodeConfluxLink(&ConfluxLink{Version: 0}); err == nil {
		t.Fatal("encode version 0 must fail")
	}
}

func TestEncodeDecodeConfluxSwitch(t *testing.T) {
	raw := EncodeConfluxSwitch(0x01020304)
	if !bytes.Equal(raw, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("switch endian %#x", raw)
	}
	n, err := DecodeConfluxSwitch(raw)
	if err != nil || n != 0x01020304 {
		t.Fatalf("switch %d %v", n, err)
	}
	if _, err := DecodeConfluxSwitch([]byte{1, 2, 3}); err == nil {
		t.Fatal("short switch must fail")
	}
}

func TestConfluxShouldMultiplex(t *testing.T) {
	for _, cmd := range []byte{
		RelayBegin, RelayData, RelayEnd, RelayConnected,
		RelayResolve, RelayResolved, RelayBeginDir, RelayXon, RelayXoff,
	} {
		if !ConfluxShouldMultiplex(cmd) {
			t.Fatalf("command %s must multiplex", RelayCmdString(cmd))
		}
	}
	for _, cmd := range []byte{
		RelaySendme, RelayExtend2, RelayConfluxLink, RelayConfluxLinked,
		RelayConfluxLinkedAck, RelayConfluxSwitch, RelayDrop,
	} {
		if ConfluxShouldMultiplex(cmd) {
			t.Fatalf("command %s must not multiplex", RelayCmdString(cmd))
		}
	}
}

func TestConfluxLinkV1HasNoStreamID(t *testing.T) {
	if RelayCmdExpectsStreamID(RelayConfluxLink) ||
		RelayCmdExpectsStreamID(RelayConfluxLinked) ||
		RelayCmdExpectsStreamID(RelayConfluxLinkedAck) ||
		RelayCmdExpectsStreamID(RelayConfluxSwitch) {
		t.Fatal("conflux control commands must not carry stream_id in v1")
	}
	rc, err := NewRelayCell(0, RelayConfluxLink, make([]byte, ConfluxLinkPayloadLen))
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
	if got.StreamID != 0 || got.Command != RelayConfluxLink || len(got.Data) != ConfluxLinkPayloadLen {
		t.Fatalf("v1 link %#v", got)
	}
}

func TestRelayCmdStringConflux(t *testing.T) {
	if RelayCmdString(RelayConfluxLink) != "RELAY_CONFLUX_LINK" {
		t.Fatal(RelayCmdString(RelayConfluxLink))
	}
	if RelayCmdString(RelayConfluxSwitch) != "RELAY_CONFLUX_SWITCH" {
		t.Fatal(RelayCmdString(RelayConfluxSwitch))
	}
}
