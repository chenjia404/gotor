package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - SHA-1 required by Tor spec for RSA fingerprints
	"crypto/x509"
	"crypto/x509/pkix"
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
	expires := time.Unix(int64(expHours)*3600, 0).UTC()
	out, err := EncodeRSAEd25519CrossCert(edPub, rsaPriv, expires)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
