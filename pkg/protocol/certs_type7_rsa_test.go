package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestVerifyType7RSACrossCert_Valid(t *testing.T) {
	chain := generateTestLinkCertChain(t)
	signing := createSignedEd25519Cert(t, 4, chain.signingPub, chain.identityPriv, chain.identityPub)
	certs := &CERTSCell{
		Certificates: []*Certificate{
			chain.type2,
			chain.type7,
			{CertType: CertTypeEd25519Signing, Ed25519Cert: signing},
		},
	}
	if err := certs.ValidateSignatures(); err != nil {
		t.Fatalf("valid type 7 RSA cross-cert rejected: %v", err)
	}
	if err := certs.ValidateRelayIdentity(chain.fingerprint, chain.identityPub); err != nil {
		t.Fatalf("identity: %v", err)
	}
}

func TestVerifyType7RSACrossCert_MissingType2(t *testing.T) {
	chain := generateTestLinkCertChain(t)
	certs := &CERTSCell{
		Certificates: []*Certificate{chain.type7},
	}
	err := certs.ValidateSignatures()
	if err == nil || !strings.Contains(err.Error(), "type 2") {
		t.Fatalf("expected type 2 required, got %v", err)
	}
}

func TestVerifyType7RSACrossCert_WrongRSA(t *testing.T) {
	chain := generateTestLinkCertChain(t)
	other := generateTestLinkCertChain(t)
	certs := &CERTSCell{
		Certificates: []*Certificate{
			other.type2,
			chain.type7,
		},
	}
	err := certs.ValidateSignatures()
	if err == nil || !strings.Contains(err.Error(), "type 7") {
		t.Fatalf("expected type 7 verify failure, got %v", err)
	}
}

func TestVerifyType7RSACrossCert_TamperedEd25519(t *testing.T) {
	chain := generateTestLinkCertChain(t)
	fake, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), chain.type7Raw...)
	copy(tampered[:32], fake)
	parsed, err := parseRSAEd25519CrossCert(tampered)
	if err != nil {
		t.Fatal(err)
	}
	certs := &CERTSCell{
		Certificates: []*Certificate{
			chain.type2,
			{
				CertType:    CertTypeEd25519Identity,
				CertBody:    tampered,
				Ed25519Cert: parsed,
			},
		},
	}
	if err := certs.ValidateSignatures(); err == nil {
		t.Fatal("tampered Ed25519 identity must fail RSA cross-cert verify")
	}
}

func TestSignAndParseType7RoundTrip(t *testing.T) {
	chain := generateTestLinkCertChain(t)
	parsed, err := parseRSAEd25519CrossCert(chain.type7Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.CertifiedKey, chain.identityPub) {
		t.Fatal("parsed Ed25519 identity mismatch")
	}
	if len(parsed.SignedBytes) != 36 {
		t.Fatalf("SignedBytes len=%d, want 36 (KEY||EXP, no SIGLEN)", len(parsed.SignedBytes))
	}
	if err := verifyRSAEd25519CrossCert(parsed, &chain.rsaPriv.PublicKey); err != nil {
		t.Fatal(err)
	}

	// 按字面 cert-spec 把 SIGLEN 纳入 FIELDS 必须失败（C Tor 不含 SIGLEN）
	wrong := &Ed25519Certificate{
		CertifiedKey: parsed.CertifiedKey,
		ExpiresAt:    parsed.ExpiresAt,
		Signature:    parsed.Signature,
		SignedBytes:  chain.type7Raw[:37],
	}
	if err := verifyRSAEd25519CrossCert(wrong, &chain.rsaPriv.PublicKey); err == nil {
		t.Fatal("FIELDS including SIGLEN must not verify")
	}
}

func TestVerifyType7RejectsShortSignature(t *testing.T) {
	pub, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cross := &Ed25519Certificate{
		CertifiedKey: make([]byte, 32),
		Signature:    make([]byte, 64),
		SignedBytes:  make([]byte, 37),
	}
	if err := verifyRSAEd25519CrossCert(cross, &pub.PublicKey); err == nil {
		t.Fatal("short RSA signature must fail")
	}
}
