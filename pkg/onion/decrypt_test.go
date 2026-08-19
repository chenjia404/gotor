package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestDecryptDescriptorNilInputs(t *testing.T) {
	_, err := DecryptDescriptor(nil, &Address{Pubkey: make([]byte, 32)}, 1)
	if err == nil {
		t.Fatal("expected error for nil descriptor")
	}
	_, err = DecryptDescriptor(&Descriptor{}, nil, 1)
	if err == nil {
		t.Fatal("expected error for nil address")
	}
	_, err = DecryptDescriptor(&Descriptor{}, &Address{Pubkey: make([]byte, 16)}, 1)
	if err == nil {
		t.Fatal("expected error for short pubkey")
	}
}

func TestDecryptDescriptorRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := &Address{Pubkey: []byte(pub), Version: 3}
	period := uint64(100)
	blinded := ComputeBlindedPubkey(pub, period)
	subcred := ComputeHSSubcredential(addr.Pubkey, blinded)
	rev := uint64(42)

	innerPlain := []byte("introduction-point aaa\nonion-key\nntor " +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n")
	innerCT := encryptHSDescLayerForTest(t, blinded, subcred, rev, "hsdir-encrypted-data", innerPlain)

	outerPlain := []byte("desc-auth-type x25519\ndesc-auth-ephemeral-key " +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)) +
		"\nencrypted\n-----BEGIN MESSAGE-----\n" +
		base64.StdEncoding.EncodeToString(innerCT) +
		"\n-----END MESSAGE-----\n")
	outerCT := encryptHSDescLayerForTest(t, blinded, subcred, rev, "hsdir-superencrypted-data", outerPlain)

	raw := []byte("hs-descriptor 3\ndescriptor-lifetime 180\nrevision-counter 42\nsuperencrypted\n-----BEGIN MESSAGE-----\n" +
		base64.StdEncoding.EncodeToString(outerCT) +
		"\n-----END MESSAGE-----\nsignature " +
		base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n")

	desc, err := ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	desc.BlindedPubkey = blinded
	desc.RevisionCounter = rev

	out, err := DecryptDescriptor(desc, addr, period)
	if err != nil {
		t.Fatalf("DecryptDescriptor: %v", err)
	}
	if len(out.IntroPoints) == 0 {
		t.Fatalf("expected intro points, got 0; inner was %q", innerPlain)
	}
}

func encryptHSDescLayerForTest(t *testing.T, secretData, subcred []byte, rev uint64, constant string, plain []byte) []byte {
	t.Helper()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	// pad to 10k multiple for realism (optional small pad)
	padded := append([]byte{}, plain...)
	for len(padded)%16 != 0 {
		padded = append(padded, 0)
	}

	secretInput := append(append([]byte{}, secretData...), subcred...)
	var revBuf [8]byte
	binary.BigEndian.PutUint64(revBuf[:], rev)
	secretInput = append(secretInput, revBuf[:]...)
	kdfIn := append(append(secretInput, salt...), constant...)
	keys := make([]byte, 32+16+32)
	sha3.ShakeSum256(keys, kdfIn)
	secretKey := keys[:32]
	iv := keys[32:48]
	macKey := keys[48:]

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.NewCTR(block, iv)
	enc := make([]byte, len(padded))
	stream.XORKeyStream(enc, padded)

	mac := hsDescMAC(macKey, salt, enc)
	out := make([]byte, 0, 16+len(enc)+32)
	out = append(out, salt...)
	out = append(out, enc...)
	out = append(out, mac...)
	return out
}
