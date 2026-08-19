package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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

func TestNtorHKDFUsesSecretInputNotKeySeed(t *testing.T) {
	nodeID := bytes.Repeat([]byte{0x11}, 20)
	serverKP, err := GenerateNtorKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handshake, clientPriv, err := NtorClientHandshake(nodeID, serverKP.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	resp, want, err := NtorServerHandshake(handshake, serverKP.Private[:], nodeID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NtorProcessResponse(resp, clientPriv, serverKP.Public[:], nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("client/server key material mismatch")
	}

	// 用客户端私钥还原 secret_input，证明 IKM=KEY_SEED 的二次 Extract 与 C Tor 不符。
	var clientX, serverY, serverB [32]byte
	copy(clientX[:], clientPriv)
	copy(serverY[:], resp[:32])
	copy(serverB[:], serverKP.Public[:])
	var sharedXY, sharedXB, clientPub [32]byte
	curve25519.ScalarMult(&sharedXY, &clientX, &serverY)
	curve25519.ScalarMult(&sharedXB, &clientX, &serverB)
	curve25519.ScalarBaseMult(&clientPub, &clientX)
	secretInput := ntorBuildSecretInput(sharedXY[:], sharedXB[:], nodeID, serverKP.Public[:], clientPub[:], serverY[:])
	keySeed, _ := ntorDerive(secretInput)

	correct, err := ntorExpandKeyMaterial(secretInput)
	if err != nil {
		t.Fatal(err)
	}
	correct = correct[:NtorKeyMaterialLen]
	if !bytes.Equal(correct, want) {
		t.Fatal("canonical expand(secret_input) must match handshake keys")
	}

	wrongReader := hkdf.New(sha256.New, keySeed, []byte(ntorTKey), []byte(ntorMExpand))
	wrong := make([]byte, NtorKeyMaterialLen)
	if _, err := io.ReadFull(wrongReader, wrong); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrong, want) {
		t.Fatal("HKDF(IKM=KEY_SEED) must differ from C Tor HKDF(IKM=secret_input)")
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
