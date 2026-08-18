package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// TestEd25519Cert_SignedWithKeyExtension_MatchesArti 对照 cert-spec 与
// Arti crates/tor-cert/src/encode.rs：ExtLen=32，不含 ExtType/ExtFlags。
func TestEd25519Cert_SignedWithKeyExtension_MatchesArti(t *testing.T) {
	identityPub, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expHours := uint32(time.Now().Add(24 * time.Hour).Unix() / 3600)
	signed := make([]byte, 0, 80)
	signed = append(signed, 1, 4) // version, type 4
	exp := make([]byte, 4)
	binary.BigEndian.PutUint32(exp, expHours)
	signed = append(signed, exp...)
	signed = append(signed, 1) // cert key type ed25519
	signed = append(signed, signingPub...)
	signed = append(signed, 1) // one extension

	// ExtLen = 32 = len(ExtData)，与 Arti SignedWithEd25519Ext::write_onto 一致
	signed = append(signed, 0, 32)
	signed = append(signed, ExtTypeSignedWithEd25519Key, 0)
	signed = append(signed, identityPub...)

	sig := ed25519.Sign(identityPriv, signed)
	raw := append(append([]byte{}, signed...), sig...)

	parsed, err := parseEd25519Certificate(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := parsed.SignedWithEd25519Key(); string(got) != string(identityPub) {
		t.Fatalf("signed-with key mismatch")
	}
	if err := parsed.VerifySignature(identityPub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	type7 := make([]byte, 0, 38)
	type7 = append(type7, identityPub...)
	type7 = append(type7, exp...)
	type7 = append(type7, 1, 0)

	payload := []byte{2}
	payload = append(payload, byte(CertTypeEd25519Identity))
	l7 := make([]byte, 2)
	binary.BigEndian.PutUint16(l7, uint16(len(type7)))
	payload = append(payload, l7...)
	payload = append(payload, type7...)
	payload = append(payload, byte(CertTypeEd25519Signing))
	l4 := make([]byte, 2)
	binary.BigEndian.PutUint16(l4, uint16(len(raw)))
	payload = append(payload, l4...)
	payload = append(payload, raw...)

	c := cell.NewCell(0, cell.CmdCerts)
	c.Payload = payload
	certs, err := ParseCERTSCell(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := certs.ValidateSignatures(); err != nil {
		t.Fatalf("ValidateSignatures: %v", err)
	}
	if err := certs.ValidateRelayIdentity("", identityPub); err != nil {
		t.Fatalf("identity: %v", err)
	}
}

func TestEd25519Cert_WrongExtLenInterpretationRejected(t *testing.T) {
	// 旧实现把 ExtLen 当成 type+flags+data。按那种错误编码的证书必须解析失败或验签失败。
	identityPub, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPub := make([]byte, 32)
	expHours := uint32(time.Now().Add(24 * time.Hour).Unix() / 3600)
	wrong := make([]byte, 0, 80)
	wrong = append(wrong, 1, 4)
	exp := make([]byte, 4)
	binary.BigEndian.PutUint32(exp, expHours)
	wrong = append(wrong, exp...)
	wrong = append(wrong, 1)
	wrong = append(wrong, signingPub...)
	wrong = append(wrong, 1)
	// 错误：ExtLen = 34（把 type+flags 算进去）
	wrong = append(wrong, 0, 34)
	wrong = append(wrong, ExtTypeSignedWithEd25519Key, 0)
	wrong = append(wrong, identityPub...)
	sig := ed25519.Sign(identityPriv, wrong)
	raw := append(append([]byte{}, wrong...), sig...)

	_, err = parseEd25519Certificate(raw)
	if err == nil {
		t.Fatal("expected parse error for ExtLen=34 (type+flags included)")
	}
}
