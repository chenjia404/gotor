package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseMicrodescriptorSameLineIdentity(t *testing.T) {
	ntor := base64.StdEncoding.EncodeToString(bytesRepeat(0x42, 32))
	ed := base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	doc := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIB\n-----END RSA PUBLIC KEY-----\n" +
		"ntor-onion-key " + ntor + "\n" +
		"id ed25519 " + ed + "\n" +
		"family $AAAA\n"

	sum := sha256.Sum256([]byte(doc))
	digest := base64.RawStdEncoding.EncodeToString(sum[:])
	relay := &Relay{Nickname: "Test", MicrodescDigest: digest}
	client := NewClient(nil)
	if err := client.parseMicrodescriptors([]byte(doc), map[string][]*Relay{digest: {relay}}); err != nil {
		t.Fatal(err)
	}
	if !relay.HasNtorKeys() && len(relay.NtorOnionKey) != 32 {
		// RSAIdentity 由共识填充；这里至少要有 ntor / ed25519
		t.Fatalf("ntor key not populated: %d", len(relay.NtorOnionKey))
	}
	if len(relay.IdentityKey) != 32 {
		t.Fatalf("ed25519 identity not populated: %d", len(relay.IdentityKey))
	}
	if len(relay.Family) != 1 || relay.Family[0] != "$AAAA" {
		t.Fatalf("family = %#v", relay.Family)
	}
}

func TestDecodeRSAIdentityBase64(t *testing.T) {
	raw := bytesRepeat(0xab, 20)
	b64 := base64.RawStdEncoding.EncodeToString(raw)
	got, err := DecodeRSAIdentity(b64)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("decoded mismatch")
	}
	hexID := fingerprintHex(raw)
	got2, err := DecodeRSAIdentity(hexID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != string(raw) {
		t.Fatalf("hex decode mismatch")
	}
}

func TestMicrodescriptorDigestNoPadding(t *testing.T) {
	doc := []byte("onion-key\nntor-onion-key AAAA\n")
	d := microdescriptorDigest(doc)
	if strings.Contains(d, "=") {
		t.Fatalf("digest must omit padding, got %q", d)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
