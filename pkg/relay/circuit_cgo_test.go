package relay

import (
	"bytes"
	"testing"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

func TestCircuitCryptoCGORoundTrip(t *testing.T) {
	keys := bytes.Repeat([]byte{0x33}, crypto.CGOKeyMaterialLen)
	relayCC, err := newCircuitCrypto(keys)
	if err != nil {
		t.Fatal(err)
	}
	if !relayCC.usesCGO() {
		t.Fatal("160 字节必须走 CGO")
	}
	client, err := crypto.NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}

	rc, err := cell.NewRelayCell(7, cell.RelayBegin, []byte("example.com:80\x00"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cell.EncodeRelayCellV1(rc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Fwd.ClientOriginate(cgoADRelay, plain); err != nil {
		t.Fatal(err)
	}

	dec, forUs, tag, err := relayCC.peelInboundWithAD(plain, cgoADRelay)
	if err != nil {
		t.Fatal(err)
	}
	if !forUs {
		t.Fatal("末端应识别客户端 originate")
	}
	if len(tag) != crypto.CGOTagLen {
		t.Fatalf("tag len %d", len(tag))
	}
	got, err := relayCC.decodeRelay(dec)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.RelayBegin || got.StreamID != 7 {
		t.Fatalf("got cmd=%d sid=%d", got.Command, got.StreamID)
	}
	if string(got.Data) != "example.com:80\x00" {
		t.Fatalf("data %q", got.Data)
	}

	reply, err := cell.NewRelayCell(7, cell.RelayConnected, nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := relayCC.originateRelay(reply)
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := client.Back.ClientBackward(cgoADRelay, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !rec {
		t.Fatal("客户端应识别中继 originate")
	}
	back, err := cell.DecodeRelayCellV1(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.Command != cell.RelayConnected || back.StreamID != 7 {
		t.Fatalf("reply cmd=%d sid=%d", back.Command, back.StreamID)
	}
}

func TestCircuitCryptoCGOMiddleWrapDoesNotOriginate(t *testing.T) {
	keys := bytes.Repeat([]byte{0x44}, crypto.CGOKeyMaterialLen)
	relayCC, err := newCircuitCrypto(keys)
	if err != nil {
		t.Fatal(err)
	}
	client, err := crypto.NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}

	inner := bytes.Repeat([]byte{0xAB}, 509)
	inner[0] = 0x7F
	wrapped, err := relayCC.wrapOutbound(inner, cgoADRelay)
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := client.Back.ClientBackward(cgoADRelay, append([]byte(nil), wrapped...))
	if err != nil {
		t.Fatal(err)
	}
	if rec {
		t.Fatal("中间跳 wrap 不得被识别为本跳 originate")
	}
}

func TestCircuitCryptoCGOOriginateRecognized(t *testing.T) {
	keys := bytes.Repeat([]byte{0x45}, crypto.CGOKeyMaterialLen)
	relayCC, err := newCircuitCrypto(keys)
	if err != nil {
		t.Fatal(err)
	}
	client, err := crypto.NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(0, cell.RelayExtended2, []byte{0, 1, 0xAA})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := relayCC.originateRelay(rc)
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := client.Back.ClientBackward(cgoADRelay, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !rec {
		t.Fatal("originate 必须 recognized")
	}
}

func TestExitRelayDataChunkCGOFitsV1(t *testing.T) {
	keys := bytes.Repeat([]byte{0x46}, crypto.CGOKeyMaterialLen)
	cc, err := newCircuitCrypto(keys)
	if err != nil {
		t.Fatal(err)
	}
	circ := &ServerCircuit{crypto: cc}
	if got := exitRelayDataChunk(circ); got != 488 {
		t.Fatalf("CGO DATA chunk %d, want 488", got)
	}
	data := bytes.Repeat([]byte{'x'}, 488)
	rc, err := cell.NewRelayCell(1, cell.RelayData, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.originateRelay(rc); err != nil {
		t.Fatalf("488 字节 CGO DATA 必须能发出: %v", err)
	}
	rcTooBig, err := cell.NewRelayCell(1, cell.RelayData, bytes.Repeat([]byte{'y'}, 498))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.originateRelay(rcTooBig); err == nil {
		t.Fatal("498 字节不得编进 CGO v1")
	}
	tor1 := &ServerCircuit{}
	tor1CC, err := newCircuitCrypto(bytes.Repeat([]byte{0x01}, 72))
	if err != nil {
		t.Fatal(err)
	}
	tor1.crypto = tor1CC
	if got := exitRelayDataChunk(tor1); got != 498 {
		t.Fatalf("tor1 DATA chunk %d, want 498", got)
	}
}

func TestCircuitCryptoTor1UnchangedByShortKeys(t *testing.T) {
	km := bytes.Repeat([]byte{0x01}, 72)
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	if cc.usesCGO() {
		t.Fatal("72 字节不得走 CGO")
	}
	if _, err := newCircuitCrypto(make([]byte, 80)); err == nil {
		t.Fatal("既非 72 也非 160 必须拒绝，不得截成 tor1")
	}
}

func TestCircuitCryptoCGORejectsWrongAD(t *testing.T) {
	keys := bytes.Repeat([]byte{0x55}, crypto.CGOKeyMaterialLen)
	relayCC, err := newCircuitCrypto(keys)
	if err != nil {
		t.Fatal(err)
	}
	client, err := crypto.NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(1, cell.RelayBeginDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cell.EncodeRelayCellV1(rc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Fwd.ClientOriginate(cgoADRelayEarly, plain); err != nil {
		t.Fatal(err)
	}
	_, forUs, _, err := relayCC.peelInboundWithAD(plain, cgoADRelay)
	if err != nil {
		t.Fatal(err)
	}
	if forUs {
		t.Fatal("AD 不一致不得识别")
	}
}
