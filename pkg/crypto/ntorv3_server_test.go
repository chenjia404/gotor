package crypto

import "testing"

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
