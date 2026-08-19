package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/opd-ai/go-tor/pkg/protocol"
	"github.com/opd-ai/go-tor/pkg/security"
)

// certsEntry 是 CERTS cell 中的一条证书。
type certsEntry struct {
	certType byte
	body     []byte
}

// buildCERTSPayload 构造入站应答 CERTS（tor-spec negotiating-channels）。
//
// 应答方必须提供：
//   - type 4 IDENTITY_V_SIGNING：中期 signing key，由 KP_relayid_ed 签名，含 signed-with-ed25519-key
//   - type 5 SIGNING_V_TLS_CERT：SHA-256(TLS X.509)，由 signing key 签名
//
// RSA 遗留身份（权威仍用指纹）再附：
//   - type 1 TLS X.509（与 TLS 握手出示的证书相同）
//   - type 2 RSA_ID_X509（本实现 TLS 证即 RSA 身份自签）
//   - type 7 RSA_ID_V_IDENTITY（RSA 交叉签 Ed25519 身份）
//
// 缺任一现行必选项则返回错误，禁止发出不完整 CERTS 让对端静默断连。
func (h *LinkProtocolHandler) buildCERTSPayload() ([]byte, error) {
	if h.keys == nil || len(h.keys.TLSCert) == 0 || h.keys.RSAPrivate == nil {
		return nil, fmt.Errorf("relay keys missing TLS certificate or RSA identity")
	}
	if len(h.keys.Ed25519Private) != ed25519.PrivateKeySize || len(h.keys.Ed25519Public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("relay keys missing Ed25519 identity")
	}
	if _, err := x509.ParseCertificate(h.keys.TLSCert); err != nil {
		return nil, fmt.Errorf("TLS certificate is not valid X.509: %w", err)
	}

	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate link signing key: %w", err)
	}

	type4, err := buildIdentitySigningCert(h.keys.Ed25519Private, signPub, expires)
	if err != nil {
		return nil, fmt.Errorf("type 4 signing cert: %w", err)
	}
	type5, err := buildTLSLinkCert(h.keys.TLSCert, signPriv, expires)
	if err != nil {
		return nil, fmt.Errorf("type 5 TLS link cert: %w", err)
	}
	type7, err := protocol.EncodeRSAEd25519CrossCert(h.keys.Ed25519Public, h.keys.RSAPrivate, expires)
	if err != nil {
		return nil, fmt.Errorf("type 7 RSA cross-cert: %w", err)
	}

	return encodeCERTSPayload([]certsEntry{
		{byte(protocol.CertTypeTLSLink), h.keys.TLSCert},
		{byte(protocol.CertTypeRSAID), h.keys.TLSCert},
		{byte(protocol.CertTypeEd25519Signing), type4},
		{byte(protocol.CertTypeEd25519TLSLink), type5},
		{byte(protocol.CertTypeEd25519Identity), type7},
	})
}

func encodeCERTSPayload(entries []certsEntry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > 255 {
		return nil, fmt.Errorf("invalid CERTS entry count: %d", len(entries))
	}
	payload := []byte{byte(len(entries))} // #nosec G115 — 已限制 1..255
	for _, e := range entries {
		clen, err := security.SafeLenToUint16(e.body)
		if err != nil {
			return nil, fmt.Errorf("certificate type %d too large: %w", e.certType, err)
		}
		payload = append(payload, e.certType)
		payload = binary.BigEndian.AppendUint16(payload, clen)
		payload = append(payload, e.body...)
	}
	return payload, nil
}

// buildIdentitySigningCert 生成 type 4：certified=KP_relaysign_ed，由 KP_relayid_ed 签名。
func buildIdentitySigningCert(idPriv ed25519.PrivateKey, signPub ed25519.PublicKey, expires time.Time) ([]byte, error) {
	if len(idPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 identity private key")
	}
	idPub, ok := idPriv.Public().(ed25519.PublicKey)
	if !ok || len(idPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 identity public key")
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 signing public key")
	}
	cert := &protocol.Ed25519Certificate{
		Version:      1,
		CertType:     uint8(protocol.CertTypeEd25519Signing),
		ExpiresAt:    expires,
		CertKeyType:  protocol.CertKeyTypeEd25519,
		CertifiedKey: append([]byte(nil), signPub...),
		Extensions: []protocol.Ed25519Extension{{
			ExtType: protocol.ExtTypeSignedWithEd25519Key,
			Flags:   0,
			ExtData: append([]byte(nil), idPub...),
		}},
	}
	protocol.SignEd25519Certificate(cert, idPriv)
	return protocol.EncodeEd25519Certificate(cert), nil
}

// buildTLSLinkCert 生成 type 5：certified=SHA-256(TLS DER)，由 KP_relaysign_ed 签名。
func buildTLSLinkCert(tlsDER []byte, signPriv ed25519.PrivateKey, expires time.Time) ([]byte, error) {
	if len(tlsDER) == 0 {
		return nil, fmt.Errorf("empty TLS certificate")
	}
	if len(signPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 signing private key")
	}
	signPub, ok := signPriv.Public().(ed25519.PublicKey)
	if !ok || len(signPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 signing public key")
	}
	sum := sha256.Sum256(tlsDER)
	cert := &protocol.Ed25519Certificate{
		Version:      1,
		CertType:     uint8(protocol.CertTypeEd25519TLSLink),
		ExpiresAt:    expires,
		CertKeyType:  protocol.CertKeyTypeSHA256OfX509,
		CertifiedKey: sum[:],
		Extensions: []protocol.Ed25519Extension{{
			ExtType: protocol.ExtTypeSignedWithEd25519Key,
			Flags:   0,
			ExtData: append([]byte(nil), signPub...),
		}},
	}
	protocol.SignEd25519Certificate(cert, signPriv)
	return protocol.EncodeEd25519Certificate(cert), nil
}
