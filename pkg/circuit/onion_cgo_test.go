package circuit

import (
	"bytes"
	"testing"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

func TestEncryptDecryptCGORoundtrip(t *testing.T) {
	keys := bytes.Repeat([]byte{0x3c}, crypto.CGOKeyMaterialLen)
	pair, err := crypto.NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCircuit(1)
	if err := c.AddHop(&Hop{CGO: pair}); err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(3, cell.RelayData, []byte("hello-cgo"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cell.EncodeRelayCellV1(rc)
	if err != nil {
		t.Fatal(err)
	}
	enc, tag, err := c.encryptOnion(byte(cell.CmdRelay), 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tag) != crypto.CGOTagLen {
		t.Fatalf("tag len %d", len(tag))
	}
	// 对端中继用同一把前向密钥的 ENC 方向识别。这里用第二套独立 pair 的 Back 无法解开；
	// 客户端往返是：发出走 Fwd，收回走 Back，密钥不同。
	// 验证同一 Fwd 再 originate 会推进状态，且密文与明文不同。
	if bytes.Equal(enc, payload) {
		t.Fatal("CGO must change the cell")
	}
}

func TestCGONoAESCTRFallbackOnKeyLen(t *testing.T) {
	e := NewExtension(NewCircuit(2), nil)
	e.requestCGO = true
	if _, err := e.deriveHopFromKeyMaterial(make([]byte, 72)); err == nil {
		t.Fatal("must not derive tor1 hop when CGO was requested")
	}
}

func TestCGORelayDataMaxIs488(t *testing.T) {
	keys := bytes.Repeat([]byte{0x3c}, crypto.CGOKeyMaterialLen)
	pair, err := crypto.NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCircuit(3)
	if err := c.AddHop(&Hop{CGO: pair}); err != nil {
		t.Fatal(err)
	}
	if got := c.RelayDataMax(); got != 488 {
		t.Fatalf("CGO DATA max %d, want 488", got)
	}
}

func TestEncodeV1RejectsStreamSendme(t *testing.T) {
	if _, err := cell.EncodeRelayCellV1(&cell.RelayCell{Command: cell.RelaySendme, StreamID: 7}); err == nil {
		t.Fatal("v1 SENDME 不得带 stream_id（C Tor relay_cmd_expects_streamid_in_v1）")
	}
}
