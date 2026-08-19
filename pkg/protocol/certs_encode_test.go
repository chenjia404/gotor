package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestEncodeRSAEd25519CrossCertRoundTrip(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G401 — 遗留 RSA-1024
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)

	raw, err := EncodeRSAEd25519CrossCert(edPub, rsaPriv, expires)
	if err != nil {
		t.Fatalf("EncodeRSAEd25519CrossCert: %v", err)
	}
	if len(raw) != 37+rsaPriv.Size() {
		t.Fatalf("wire length = %d, want %d", len(raw), 37+rsaPriv.Size())
	}
	if !bytes.Equal(raw[:32], edPub) {
		t.Fatal("certified Ed25519 identity mismatch")
	}

	parsed, err := parseRSAEd25519CrossCert(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := verifyRSAEd25519CrossCert(parsed, &rsaPriv.PublicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if _, err := EncodeRSAEd25519CrossCert(nil, rsaPriv, expires); err == nil {
		t.Fatal("expected error for empty Ed25519 identity")
	}
	if _, err := EncodeRSAEd25519CrossCert(edPub, nil, expires); err == nil {
		t.Fatal("expected error for nil RSA key")
	}
}
