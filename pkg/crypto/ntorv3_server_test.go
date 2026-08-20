package crypto

import (
	"bytes"
	"testing"
)

func TestNtorV3ServerHandshakeRoundTrip(t *testing.T) {
	onion, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	edID := make([]byte, 32)
	for i := range edID {
		edID[i] = byte(i + 3)
	}
	ver := NtorV3CircuitVerification
	cm, err := EncodeNtorV3ClientMsg(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	skin, st, err := NtorV3ClientHandshake(edID, onion.Public[:], ver, cm)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Wipe()

	smPlain := EncodeNtorV3Extensions([]NtorV3Extension{{Type: NtorV3ExtCCResponse, Data: []byte{31}}})
	resp, serverKM, err := NtorV3ServerHandshake(skin, edID, onion.Private[:], ver, smPlain)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverKM) != NtorV3KeyMaterialLen {
		t.Fatalf("server km %d", len(serverKM))
	}

	clientKM, gotSM, err := NtorV3ProcessResponse(resp, st, ver)
	if err != nil {
		t.Fatal(err)
	}
	if string(clientKM) != string(serverKM) {
		t.Fatal("client/server key material mismatch")
	}
	inc, ok, err := ParseCCSendmeInc(gotSM)
	if err != nil || !ok || inc != 31 {
		t.Fatalf("CC response: ok=%v inc=%d err=%v", ok, inc, err)
	}
}

func TestNtorV3ServerHandshakeWithNonce(t *testing.T) {
	onion, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	edID := make([]byte, 32)
	for i := range edID {
		edID[i] = byte(i + 7)
	}
	ver := NtorV3CircuitVerification
	cm, err := EncodeNtorV3ClientMsg(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	skin, st, err := NtorV3ClientHandshake(edID, onion.Public[:], ver, cm)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Wipe()
	smPlain := EncodeNtorV3Extensions([]NtorV3Extension{{Type: NtorV3ExtCCResponse, Data: []byte{31}}})
	_, km, nonce, err := NtorV3ServerHandshakeWithNonce(skin, edID, onion.Private[:], ver, smPlain)
	if err != nil {
		t.Fatal(err)
	}
	if len(km) != NtorV3KeyMaterialLen || len(nonce) != NtorCircNonceLen {
		t.Fatalf("km=%d nonce=%d", len(km), len(nonce))
	}
}

func TestNtorV3ServerHandshakeCGOKeyLen(t *testing.T) {
	onion, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	edID := bytes.Repeat([]byte{0x09}, 32)
	ver := NtorV3CircuitVerification
	cm, err := EncodeNtorV3ClientMsg(true, []SubprotoCap{{ProtocolID: ProtoRelay, Cap: CapRelayCGO}})
	if err != nil {
		t.Fatal(err)
	}
	skin, st, err := NtorV3ClientHandshake(edID, onion.Public[:], ver, cm)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Wipe()
	st.SetKeyMaterialLen(CGOKeyMaterialLen)

	smPlain := EncodeNtorV3Extensions([]NtorV3Extension{{Type: NtorV3ExtCCResponse, Data: []byte{31}}})
	resp, serverKM, err := NtorV3ServerHandshake(skin, edID, onion.Private[:], ver, smPlain)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverKM) != CGOKeyMaterialLen {
		t.Fatalf("server km %d, want %d", len(serverKM), CGOKeyMaterialLen)
	}
	clientKM, _, err := NtorV3ProcessResponse(resp, st, ver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientKM, serverKM) {
		t.Fatal("CGO key material mismatch")
	}
}

func TestNtorV3ServerHandshakeNoCGOStays72(t *testing.T) {
	onion, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	edID := bytes.Repeat([]byte{0x0A}, 32)
	ver := NtorV3CircuitVerification
	cm, err := EncodeNtorV3ClientMsg(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	skin, st, err := NtorV3ClientHandshake(edID, onion.Public[:], ver, cm)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Wipe()
	smPlain := EncodeNtorV3Extensions([]NtorV3Extension{{Type: NtorV3ExtCCResponse, Data: []byte{31}}})
	_, serverKM, err := NtorV3ServerHandshake(skin, edID, onion.Private[:], ver, smPlain)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverKM) != NtorV3KeyMaterialLen {
		t.Fatalf("未请求 CGO 时 km=%d, want 72", len(serverKM))
	}
}

func TestNtorV3ServerHandshakeBadSubprotoFails(t *testing.T) {
	onion, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	edID := bytes.Repeat([]byte{0x0B}, 32)
	ver := NtorV3CircuitVerification
	// type 3 长度为奇数：畸形，必须失败握手，不得回退 72 字节 tor1。
	cm := EncodeNtorV3Extensions([]NtorV3Extension{
		{Type: NtorV3ExtSubprotoRequest, Data: []byte{0x02}},
	})
	skin, st, err := NtorV3ClientHandshake(edID, onion.Public[:], ver, cm)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Wipe()
	_, km, err := NtorV3ServerHandshake(skin, edID, onion.Private[:], ver, EncodeNtorV3Extensions(nil))
	if err == nil {
		t.Fatalf("畸形 type 3 必须失败，却得到 km=%d", len(km))
	}
}
