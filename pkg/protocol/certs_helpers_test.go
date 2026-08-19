package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - SHA-1 required by Tor spec for RSA fingerprints
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// type7IdentityCertificate 构造仅含 Ed25519 身份公钥的 type 7 条目。
// type 4 的 CertifiedKey 是 signing key，不能当作 identity。
// 不含 RSA 交叉签名，只供 ValidateRelayIdentity 使用。
func type7IdentityCertificate(identity []byte) *Certificate {
	key := append([]byte(nil), identity...)
	return &Certificate{
		CertType: CertTypeEd25519Identity,
		Ed25519Cert: &Ed25519Certificate{
			CertType:     7,
			CertifiedKey: key,
		},
	}
}

type testLinkCertChain struct {
	rsaPriv      *rsa.PrivateKey
	rsaCert      *x509.Certificate
	rsaDER       []byte
	fingerprint  string
	identityPub  ed25519.PublicKey
	identityPriv ed25519.PrivateKey
	signingPub   ed25519.PublicKey
	type2        *Certificate
	type7        *Certificate
	type7Raw     []byte
}

func generateTestLinkCertChain(t *testing.T) *testLinkCertChain {
	t.Helper()
	// type 7 的 SIGLEN 只有 1 字节，线上遗留 RSA identity 仍是 1024-bit（128 字节签名）。
	// 2048-bit 的 256 字节签名会溢出成 0。这不是主身份：主身份是下面的 Ed25519。
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G401
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Tor RSA Identity"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rsaPriv.PublicKey, rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fp := fmt.Sprintf("%X", sha1.Sum(x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey))) // #nosec G401

	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expHours := uint32(time.Now().Add(365*24*time.Hour).Unix() / 3600)
	type7Raw := signRSAEd25519CrossCert(t, rsaPriv, idPub, expHours)
	type7Parsed, err := parseRSAEd25519CrossCert(type7Raw)
	if err != nil {
		t.Fatal(err)
	}

	return &testLinkCertChain{
		rsaPriv:      rsaPriv,
		rsaCert:      x509Cert,
		rsaDER:       der,
		fingerprint:  fp,
		identityPub:  idPub,
		identityPriv: idPriv,
		signingPub:   signPub,
		type2: &Certificate{
			CertType: CertTypeRSAID,
			CertBody: der,
			X509Cert: x509Cert,
		},
		type7: &Certificate{
			CertType:    CertTypeEd25519Identity,
			CertBody:    type7Raw,
			Ed25519Cert: type7Parsed,
		},
		type7Raw: type7Raw,
	}
}

func signRSAEd25519CrossCert(t *testing.T, rsaPriv *rsa.PrivateKey, edPub ed25519.PublicKey, expHours uint32) []byte {
	t.Helper()
	fields := make([]byte, 0, 36)
	fields = append(fields, edPub...)
	exp := make([]byte, 4)
	binary.BigEndian.PutUint32(exp, expHours)
	fields = append(fields, exp...)
	if rsaPriv.Size() > 255 {
		t.Fatalf("RSA signature length %d exceeds SIGLEN (1 byte)", rsaPriv.Size())
	}

	// 与 C Tor 一致：只签 PREFIX || KEY || EXP，SIGLEN 写在签名之外
	msg := append([]byte(rsaEd25519CrossCertPrefix), fields...)
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPriv, 0, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != rsaPriv.Size() {
		t.Fatalf("RSA sig len %d != key size %d", len(sig), rsaPriv.Size())
	}
	out := make([]byte, 0, len(fields)+1+len(sig))
	out = append(out, fields...)
	out = append(out, byte(len(sig)))
	out = append(out, sig...)
	return out
}
