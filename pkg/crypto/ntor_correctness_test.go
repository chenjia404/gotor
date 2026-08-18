package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNtorSpecHandshakeRoundTrip(t *testing.T) {
	nodeID := make([]byte, NtorNodeIDLen)
	if _, err := rand.Read(nodeID); err != nil {
		t.Fatal(err)
	}

	serverKP, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	handshake, clientPriv, err := NtorClientHandshake(nodeID, serverKP.Public[:])
	if err != nil {
		t.Fatalf("NtorClientHandshake: %v", err)
	}
	if len(handshake) != NtorHandshakeLen {
		t.Fatalf("handshake length %d", len(handshake))
	}
	if !bytes.Equal(handshake[0:20], nodeID) {
		t.Fatal("NODEID must be the 20-byte RSA digest, not a truncated Ed25519 key")
	}
	if !bytes.Equal(handshake[20:52], serverKP.Public[:]) {
		t.Fatal("KEYID mismatch")
	}

	resp, serverKeys, err := NtorServerHandshake(handshake, serverKP.Private[:], nodeID)
	if err != nil {
		t.Fatalf("NtorServerHandshake: %v", err)
	}
	clientKeys, err := NtorProcessResponse(resp, clientPriv, serverKP.Public[:], nodeID)
	if err != nil {
		t.Fatalf("NtorProcessResponse: %v", err)
	}
	if !bytes.Equal(serverKeys, clientKeys) {
		t.Fatalf("key material mismatch\nserver %x\nclient %x", serverKeys, clientKeys)
	}
	if len(clientKeys) != NtorKeyMaterialLen {
		t.Fatalf("key material length %d", len(clientKeys))
	}
}

func TestNtorRejectsWrongIdentityLength(t *testing.T) {
	_, _, err := NtorClientHandshake(make([]byte, 32), make([]byte, 32))
	if err == nil {
		t.Fatal("32-byte Ed25519 identity must be rejected as NODEID")
	}
	_, _, err = NtorClientHandshake(make([]byte, 20), make([]byte, 32))
	if err == nil {
		t.Fatal("all-zero keys must be rejected")
	}
}

func TestNtorRejectsWrongAUTH(t *testing.T) {
	nodeID := bytes.Repeat([]byte{0x11}, 20)
	serverKP, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handshake, clientPriv, err := NtorClientHandshake(nodeID, serverKP.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := NtorServerHandshake(handshake, serverKP.Private[:], nodeID)
	if err != nil {
		t.Fatal(err)
	}
	resp[40] ^= 0xff
	_, err = NtorProcessResponse(resp, clientPriv, serverKP.Public[:], nodeID)
	if err == nil {
		t.Fatal("tampered AUTH must fail")
	}
}
