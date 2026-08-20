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

func TestHandleIntroduce1ForwardsAndAcks(t *testing.T) {
	keys, err := onion.GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytesRepeatHS(0x11, 20)
	est, err := onion.BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, nonce)
	if err != nil {
		t.Fatal(err)
	}
	kmSvc := bytesRepeatHS(0x22, 72)
	kmCli := bytesRepeatHS(0x23, 72)
	svcCC, err := newCircuitCrypto(kmSvc)
	if err != nil {
		t.Fatal(err)
	}
	cliCC, err := newCircuitCrypto(kmCli)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerCircuit{CircuitID: 21, crypto: svcCC, circNonce: nonce}
	cli := &ServerCircuit{CircuitID: 22, crypto: cliCC}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	svcConn := newMockConn()
	cliConn := newMockConn()
	if err := h.forwarder.handleEstablishIntro(svc, svcConn, est); err != nil {
		t.Fatal(err)
	}
	intro1 := testIntroduce1Payload(keys.AuthPublic)
	if err := h.forwarder.handleIntroduce1(cli, cliConn, intro1); err != nil {
		t.Fatalf("INTRODUCE1: %v", err)
	}
	svcCells := decodeAllRelays(t, svcConn, kmSvc)
	if len(svcCells) != 2 {
		t.Fatalf("服务电路应先 INTRO_ESTABLISHED 再 INTRODUCE2，got %d", len(svcCells))
	}
	if svcCells[0].Command != cell.RelayIntroEstablished {
		t.Fatalf("第一格 cmd %d want INTRO_ESTABLISHED", svcCells[0].Command)
	}
	fwd := svcCells[1]
	if fwd.Command != cell.RelayIntroduce2 || !bytes.Equal(fwd.Data, intro1) {
		t.Fatalf("INTRODUCE2 cmd=%d data=%x", fwd.Command, fwd.Data)
	}
	ack := lastDecodedRelay(t, cliConn, kmCli)
	if ack.Command != cell.RelayIntroduceAck {
		t.Fatalf("ack cmd %d", ack.Command)
	}
	if !bytes.Equal(ack.Data, introAckPayload(introAckSuccess)) {
		t.Fatalf("ack %x", ack.Data)
	}
}

func TestHandleIntroduce1UnknownAuth(t *testing.T) {
	km := bytesRepeatHS(0x24, 72)
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	cli := &ServerCircuit{CircuitID: 23, crypto: cc}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	conn := newMockConn()
	if err := h.forwarder.handleIntroduce1(cli, conn, testIntroduce1Payload(bytesRepeatHS(0xab, 32))); err != nil {
		t.Fatal(err)
	}
	ack := decodeLastRelay(t, conn, km)
	if ack.Command != cell.RelayIntroduceAck || !bytes.Equal(ack.Data, introAckPayload(introAckNotRecognized)) {
		t.Fatalf("want NOT_RECOGNIZED, cmd=%d data=%x", ack.Command, ack.Data)
	}
}

func TestHandleRendezvous1JoinsCircuits(t *testing.T) {
	kmCli := bytesRepeatHS(0x44, 72)
	kmSvc := bytesRepeatHS(0x45, 72)
	cliCC, err := newCircuitCrypto(kmCli)
	if err != nil {
		t.Fatal(err)
	}
	svcCC, err := newCircuitCrypto(kmSvc)
	if err != nil {
		t.Fatal(err)
	}
	cli := &ServerCircuit{CircuitID: 31, crypto: cliCC}
	svc := &ServerCircuit{CircuitID: 32, crypto: svcCC}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	cliConn := newMockConn()
	svcConn := newMockConn()
	cookie := bytesRepeatHS(0x5a, 20)
	if err := h.forwarder.handleEstablishRendezvous(cli, cliConn, cookie); err != nil {
		t.Fatal(err)
	}
	hs := []byte{0x11, 0x22, 0x33, 0x44}
	rend1 := append(append([]byte{}, cookie...), hs...)
	if err := h.forwarder.handleRendezvous1(svc, svcConn, rend1); err != nil {
		t.Fatal(err)
	}
	cliCells := decodeAllRelays(t, cliConn, kmCli)
	if len(cliCells) != 2 {
		t.Fatalf("客户端电路应先 RENDEZVOUS_ESTABLISHED 再 RENDEZVOUS2，got %d", len(cliCells))
	}
	if cliCells[0].Command != cell.RelayRendezvousEstablished {
		t.Fatalf("第一格 cmd %d want RENDEZVOUS_ESTABLISHED", cliCells[0].Command)
	}
	got := cliCells[1]
	if got.Command != cell.RelayRendezvous2 || !bytes.Equal(got.Data, hs) {
		t.Fatalf("RENDEZVOUS2 cmd=%d data=%x", got.Command, got.Data)
	}
	if cli.joinedCirc != svc || svc.joinedCirc != cli {
		t.Fatal("会合点必须把两条电路拼起来")
	}
	replay := &ServerCircuit{CircuitID: 34, crypto: svcCC}
	if err := h.forwarder.handleRendezvous1(replay, newMockConn(), rend1); err == nil {
		t.Fatal("同一 cookie 不得再被 RENDEZVOUS1 使用")
	}
	if cli.joinedCirc != svc {
		t.Fatal("重放不得拆掉已会合电路")
	}
}

func TestHandleRendezvous1OnIntroRestoresCookie(t *testing.T) {
	keys, err := onion.GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytesRepeatHS(0x11, 20)
	est, err := onion.BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, nonce)
	if err != nil {
		t.Fatal(err)
	}
	kmIntro := bytesRepeatHS(0x49, 72)
	kmCli := bytesRepeatHS(0x4a, 72)
	kmSvc := bytesRepeatHS(0x4b, 72)
	introCC, err := newCircuitCrypto(kmIntro)
	if err != nil {
		t.Fatal(err)
	}
	cliCC, err := newCircuitCrypto(kmCli)
	if err != nil {
		t.Fatal(err)
	}
	svcCC, err := newCircuitCrypto(kmSvc)
	if err != nil {
		t.Fatal(err)
	}
	intro := &ServerCircuit{CircuitID: 38, crypto: introCC, circNonce: nonce}
	cli := &ServerCircuit{CircuitID: 39, crypto: cliCC}
	svc := &ServerCircuit{CircuitID: 40, crypto: svcCC}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	if err := h.forwarder.handleEstablishIntro(intro, newMockConn(), est); err != nil {
		t.Fatal(err)
	}
	cookie := bytesRepeatHS(0x5d, 20)
	if err := h.forwarder.handleEstablishRendezvous(cli, newMockConn(), cookie); err != nil {
		t.Fatal(err)
	}
	rend1 := append(append([]byte{}, cookie...), 0x42)
	if err := h.forwarder.handleRendezvous1(intro, newMockConn(), rend1); err == nil {
		t.Fatal("引言电路上的 RENDEZVOUS1 必须失败")
	}
	if err := h.forwarder.handleRendezvous1(svc, newMockConn(), rend1); err != nil {
		t.Fatalf("占用电路失败后 cookie 必须仍可会合: %v", err)
	}
	if cli.joinedCirc != svc {
		t.Fatal("恢复后的 cookie 必须能把电路拼起来")
	}
}

func TestHandleRendezvous1RejectsSameCircuit(t *testing.T) {
	km := bytesRepeatHS(0x46, 72)
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	circ := &ServerCircuit{CircuitID: 35, crypto: cc}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	conn := newMockConn()
	cookie := bytesRepeatHS(0x5b, 20)
	if err := h.forwarder.handleEstablishRendezvous(circ, conn, cookie); err != nil {
		t.Fatal(err)
	}
	if err := h.forwarder.handleRendezvous1(circ, conn, cookie); err == nil {
		t.Fatal("RENDEZVOUS1 不得落在同一会合电路上")
	}
}

func TestJoinedCircuitsForwardRelay(t *testing.T) {
	kmCli := bytesRepeatHS(0x47, 72)
	kmSvc := bytesRepeatHS(0x48, 72)
	cliCC, err := newCircuitCrypto(kmCli)
	if err != nil {
		t.Fatal(err)
	}
	svcCC, err := newCircuitCrypto(kmSvc)
	if err != nil {
		t.Fatal(err)
	}
	cli := &ServerCircuit{CircuitID: 36, crypto: cliCC}
	svc := &ServerCircuit{CircuitID: 37, crypto: svcCC}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	h.circuits[cli.CircuitID] = cli
	h.circuits[svc.CircuitID] = svc
	cliConn := newMockConn()
	svcConn := newMockConn()
	cookie := bytesRepeatHS(0x5c, 20)
	if err := h.forwarder.handleEstablishRendezvous(cli, cliConn, cookie); err != nil {
		t.Fatal(err)
	}
	rend1 := append(append([]byte{}, cookie...), 0x99)
	if err := h.forwarder.handleRendezvous1(svc, svcConn, rend1); err != nil {
		t.Fatal(err)
	}
	enc := encryptInboundHS(t, kmSvc, 7, cell.RelayData, []byte("hello"))
	c := &cell.Cell{CircID: svc.CircuitID, Command: cell.CmdRelay, Payload: enc}
	if err := h.forwarder.handleLocalRelayCell(t.Context(), svc.CircuitID, c, svcConn); err != nil {
		t.Fatal(err)
	}
	fwd := lastDecodedRelay(t, cliConn, kmCli)
	if fwd.Command != cell.RelayData || fwd.StreamID != 7 || !bytes.Equal(fwd.Data, []byte("hello")) {
		t.Fatalf("会合后 DATA 必须转到对端 cmd=%d sid=%d data=%x", fwd.Command, fwd.StreamID, fwd.Data)
	}
}

func TestHandleRendezvous1UnknownCookie(t *testing.T) {
	circ := &ServerCircuit{CircuitID: 33}
	h := NewCircuitHandler(&RelayKeys{NtorOnionKey: bytesRepeatHS(0x33, 32)}, nil)
	if err := h.forwarder.handleRendezvous1(circ, newMockConn(), bytesRepeatHS(0x00, 24)); err == nil {
		t.Fatal("unknown cookie must fail")
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

func lastDecodedRelay(t *testing.T, conn *mockConn, km []byte) *cell.RelayCell {
	t.Helper()
	all := decodeAllRelays(t, conn, km)
	if len(all) == 0 {
		t.Fatal("no RELAY cells")
	}
	return all[len(all)-1]
}

func decodeLastRelay(t *testing.T, conn *mockConn, km []byte) *cell.RelayCell {
	t.Helper()
	return lastDecodedRelay(t, conn, km)
}

func decodeAllRelays(t *testing.T, conn *mockConn, km []byte) []*cell.RelayCell {
	t.Helper()
	if len(conn.writeData) < cell.CellSize {
		t.Fatalf("no cell written: %d", len(conn.writeData))
	}
	// 同一套 Kb 按发送顺序推进；每格 newCircuitCrypto 会解不开第二格。
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(conn.writeData)
	var out []*cell.RelayCell
	for r.Len() >= cell.CellSize {
		c, err := cell.DecodeCell(r)
		if err != nil {
			t.Fatal(err)
		}
		if c.Command != cell.CmdRelay {
			continue
		}
		plain, err := decryptOutboundForTest(cc, c.Payload)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := cell.DecodeRelayCell(plain)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rc)
	}
	return out
}

func encryptInboundHS(t *testing.T, km []byte, streamID uint16, cmd byte, data []byte) []byte {
	t.Helper()
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(streamID, cmd, data)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 509 {
		pad := make([]byte, 509)
		copy(pad, plain)
		plain = pad
	}
	enc := append([]byte(nil), plain...)
	enc[1], enc[2] = 0, 0
	enc[5], enc[6], enc[7], enc[8] = 0, 0, 0, 0
	cp := append([]byte(nil), enc...)
	if _, err := cc.fwdDigest.Write(cp); err != nil {
		t.Fatal(err)
	}
	sum := cc.fwdDigest.Sum(nil)
	copy(enc[5:9], sum[:4])
	cc.fwdCipher.XORKeyStream(enc, enc)
	return enc
}

func decryptOutboundForTest(cc *circuitCrypto, enc []byte) ([]byte, error) {
	out := append([]byte(nil), enc...)
	cc.bwdCipher.XORKeyStream(out, out)
	return out, nil
}

func testIntroduce1Payload(auth []byte) []byte {
	p := make([]byte, introduce1LegacyKeyLen+3+len(auth)+1)
	p[introduce1LegacyKeyLen] = introduce1AuthKeyTypeV3
	p[introduce1LegacyKeyLen+2] = byte(len(auth))
	copy(p[introduce1LegacyKeyLen+3:], auth)
	return p
}

func bytesRepeatHS(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
