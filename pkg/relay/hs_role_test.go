package relay

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/onion"
	"golang.org/x/crypto/curve25519"
)

func TestHandleEstablishIntroAcceptsValidPayload(t *testing.T) {
	keys, err := onion.GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytesRepeatHS(0x11, 20)
	payload, err := onion.BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, nonce)
	if err != nil {
		t.Fatal(err)
	}
	km := bytesRepeatHS(0x22, 72)
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	circ := &ServerCircuit{CircuitID: 7, crypto: cc, circNonce: nonce}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	conn := newMockConn()
	if err := h.forwarder.handleEstablishIntro(circ, conn, payload); err != nil {
		t.Fatalf("handleEstablishIntro: %v", err)
	}
	if len(circ.introAuth) != ed25519.PublicKeySize {
		t.Fatalf("introAuth len %d", len(circ.introAuth))
	}
	got := decodeLastRelay(t, conn, km)
	if got.Command != cell.RelayIntroEstablished {
		t.Fatalf("cmd %d want INTRO_ESTABLISHED=%d", got.Command, cell.RelayIntroEstablished)
	}
	if got.StreamID != 0 {
		t.Fatalf("stream %d", got.StreamID)
	}
	if err := h.forwarder.handleEstablishIntro(circ, conn, payload); err == nil {
		t.Fatal("second ESTABLISH_INTRO must fail")
	}
}

func TestHandleEstablishIntroRejectsBadMAC(t *testing.T) {
	keys, err := onion.GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := onion.BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, bytesRepeatHS(0x11, 20))
	if err != nil {
		t.Fatal(err)
	}
	circ := &ServerCircuit{CircuitID: 8, circNonce: bytesRepeatHS(0x99, 20)}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	conn := newMockConn()
	if err := h.forwarder.handleEstablishIntro(circ, conn, payload); err == nil {
		t.Fatal("bad MAC must fail")
	}
}

func TestRejectHSControlNonzeroStream(t *testing.T) {
	circ := &ServerCircuit{CircuitID: 11}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	conn := newMockConn()
	if err := h.forwarder.rejectHSControlStream(circ, conn, "ESTABLISH_INTRO"); err == nil {
		t.Fatal("nonzero stream must fail")
	}
}

func TestHandleEstablishRendezvous(t *testing.T) {
	km := bytesRepeatHS(0x44, 72)
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	circ := &ServerCircuit{CircuitID: 9, crypto: cc}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	conn := newMockConn()
	cookie := bytesRepeatHS(0x5a, 20)
	if err := h.forwarder.handleEstablishRendezvous(circ, conn, cookie); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(circ.rendCookie, cookie) {
		t.Fatalf("cookie mismatch")
	}
	got := decodeLastRelay(t, conn, km)
	if got.Command != cell.RelayRendezvousEstablished {
		t.Fatalf("cmd %d want RENDEZVOUS_ESTABLISHED=%d", got.Command, cell.RelayRendezvousEstablished)
	}
	if err := h.forwarder.handleEstablishRendezvous(circ, conn, cookie); err == nil {
		t.Fatal("second ESTABLISH_RENDEZVOUS must fail")
	}
}

func TestCreate2StoresCircNonceForIntro(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewCircuitHandler(keys, nil)
	clientKey, err := crypto.GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var serverNtorPriv [32]byte
	copy(serverNtorPriv[:], keys.NtorOnionKey)
	var serverNtorPub [32]byte
	curve25519.ScalarBaseMult(&serverNtorPub, &serverNtorPriv)
	handshake := make([]byte, 84)
	copy(handshake[0:20], keys.RSANodeID())
	copy(handshake[20:52], serverNtorPub[:])
	copy(handshake[52:84], clientKey.Public[:])
	payload := make([]byte, 4+84)
	payload[1] = 0x02
	payload[3] = 84
	copy(payload[4:], handshake)
	conn := newMockConn()
	if err := handler.HandleCellFromConnection(conn, &cell.Cell{CircID: 3, Command: cell.CmdCreate2, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	circ, ok := handler.GetCircuit(3)
	if !ok || len(circ.circNonce) != 20 {
		t.Fatalf("CREATE2 must store 20-byte circ_nonce, ok=%v len=%d", ok, len(circ.circNonce))
	}
}

func TestDescriptorDoesNotAdvertiseHSRoles(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	desc, err := GenerateServerDescriptor(keys, &DescriptorConfig{
		Nickname: "HSRoleLatch",
		Address:  "192.0.2.2",
		ORPort:   9001,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(desc.RawDescriptor)
	for _, tok := range []string{"HSDir=", "HSIntro=", "HSRend=", "Relay=5", "Relay=6"} {
		if bytes.Contains([]byte(raw), []byte(tok)) {
			t.Fatalf("未实现完整 HS 中继角色前禁止 proto 含 %s", tok)
		}
	}
}

func decodeLastRelay(t *testing.T, conn *mockConn, km []byte) *cell.RelayCell {
	t.Helper()
	if len(conn.writeData) < cell.CellSize {
		t.Fatalf("no cell written: %d", len(conn.writeData))
	}
	// 可能先有 CREATED2；取最后一格。
	raw := conn.writeData[len(conn.writeData)-cell.CellSize:]
	c, err := cell.DecodeCell(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Command != cell.CmdRelay {
		t.Fatalf("last cell cmd %d", c.Command)
	}
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptOutboundForTest(cc, c.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.DecodeRelayCell(plain)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func decryptOutboundForTest(cc *circuitCrypto, enc []byte) ([]byte, error) {
	out := append([]byte(nil), enc...)
	cc.bwdCipher.XORKeyStream(out, out)
	return out, nil
}

func bytesRepeatHS(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
