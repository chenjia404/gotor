// Package protocol provides CERTS cell parsing and validation per tor-spec.txt §4.2
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - SHA-1 required by Tor spec for RSA fingerprints
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// rsaEd25519CrossCertPrefix 是 type 7 交叉证书的签名前缀。
//
// 现代中继的主身份是 Ed25519（type 4/5/7 的 certified key、microdesc `id ed25519`）。
// RSA-1024 已不是流量加密或电路握手密钥，只作为共识 `r` 行指纹 / ntor NODEID
// 的遗留身份，并由 type 7 把它绑定到 Ed25519。
//
// cert-spec 写 FIELDS 为「除 SIGNATURE 外的全部字段」（含 SIGLEN），
// 但 C Tor / 真实 CERTS 的 signed payload 是 PREFIX || KEY || EXP（36 字节），不含 SIGLEN。
// 以能通过 mainnet 的 C Tor 行为为准。
const rsaEd25519CrossCertPrefix = "Tor TLS RSA/Ed25519 cross-certificate"

// rsaEd25519CrossCertSignedLen 是 KEY(32)+EXPIRATION(4)。
const rsaEd25519CrossCertSignedLen = 36

// ExtTypeSignedWithEd25519Key 是 cert-spec 的 signed-with-ed25519-key 扩展。
// ExtLen=32，ExtData 为签名所用的 Ed25519 公钥。
const ExtTypeSignedWithEd25519Key uint8 = 0x04

// CertType represents the type of certificate in a CERTS cell
// Per tor-spec.txt §4.2, different cert types serve different purposes
type CertType byte

const (
	// CertTypeTLSLink is a TLS link certificate (type 1)
	CertTypeTLSLink CertType = 0x01
	// CertTypeRSAID is an RSA identity certificate (type 2)
	CertTypeRSAID CertType = 0x02
	// CertTypeRSAAuth is an RSA authentication certificate (type 3)
	CertTypeRSAAuth CertType = 0x03
	// CertTypeEd25519Signing is an Ed25519 signing key certificate (type 4)
	CertTypeEd25519Signing CertType = 0x04
	// CertTypeEd25519TLSLink is an Ed25519 TLS link certificate (type 5)
	CertTypeEd25519TLSLink CertType = 0x05
	// CertTypeEd25519Auth is an Ed25519 authentication certificate (type 6)
	CertTypeEd25519Auth CertType = 0x06
	// CertTypeEd25519Identity is an RSA cross-certification of Ed25519 identity (type 7)
	CertTypeEd25519Identity CertType = 0x07
)

// String returns a human-readable representation of the cert type
func (ct CertType) String() string {
	switch ct {
	case CertTypeTLSLink:
		return "TLS_LINK"
	case CertTypeRSAID:
		return "RSA_ID"
	case CertTypeRSAAuth:
		return "RSA_AUTH"
	case CertTypeEd25519Signing:
		return "ED25519_SIGNING"
	case CertTypeEd25519TLSLink:
		return "ED25519_TLS_LINK"
	case CertTypeEd25519Auth:
		return "ED25519_AUTH"
	case CertTypeEd25519Identity:
		return "ED25519_IDENTITY"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", ct)
	}
}

// Certificate represents a single certificate from a CERTS cell
type Certificate struct {
	CertType CertType
	CertBody []byte
	// Parsed X.509 certificate (for RSA/TLS certs)
	X509Cert *x509.Certificate
	// Parsed Ed25519 certificate (for Ed25519 certs)
	Ed25519Cert *Ed25519Certificate
}

// Ed25519Certificate represents a Tor Ed25519 certificate per cert-spec.txt
type Ed25519Certificate struct {
	Version      uint8
	CertType     uint8
	ExpiresAt    time.Time
	CertKeyType  uint8
	CertifiedKey []byte
	Extensions   []Ed25519Extension
	Signature    []byte
	// SignedBytes 是签名覆盖的原始字节（不含 SIGNATURE）。
	// 验签必须用线上字节，禁止按字段重编码（ExtLen 历史实现曾算错）。
	SignedBytes []byte
}

// Ed25519Extension represents an extension in an Ed25519 certificate
type Ed25519Extension struct {
	ExtType uint8
	Flags   uint8
	ExtData []byte
}

// CERTSCell represents a parsed CERTS cell
type CERTSCell struct {
	Certificates []*Certificate
}

// ParseCERTSCell parses a CERTS cell payload per tor-spec.txt §4.2
// Format:
//
//	N             [1 octet]   Number of certificates
//	N times:
//	  CertType    [1 octet]   Certificate type
//	  CLEN        [2 octets]  Certificate length (big-endian)
//	  Certificate [CLEN bytes] Certificate body
func ParseCERTSCell(cellData *cell.Cell) (*CERTSCell, error) {
	if cellData.Command != cell.CmdCerts {
		return nil, fmt.Errorf("not a CERTS cell: got %s", cellData.Command)
	}

	payload := cellData.Payload
	if len(payload) < 1 {
		return nil, fmt.Errorf("CERTS cell payload too short: %d bytes", len(payload))
	}

	numCerts := int(payload[0])
	offset := 1

	certs := &CERTSCell{
		Certificates: make([]*Certificate, 0, numCerts),
	}

	for i := 0; i < numCerts; i++ {
		if offset+3 > len(payload) {
			return nil, fmt.Errorf("truncated certificate header at offset %d", offset)
		}

		certType := CertType(payload[offset])
		certLen := binary.BigEndian.Uint16(payload[offset+1 : offset+3])
		offset += 3

		if offset+int(certLen) > len(payload) {
			return nil, fmt.Errorf("truncated certificate body: expected %d bytes at offset %d", certLen, offset)
		}

		certBody := payload[offset : offset+int(certLen)]
		offset += int(certLen)

		cert := &Certificate{
			CertType: certType,
			CertBody: make([]byte, len(certBody)),
		}
		copy(cert.CertBody, certBody)

		if err := parseCertificateBody(cert); err != nil {
			switch cert.CertType {
			case CertTypeEd25519Signing, CertTypeEd25519TLSLink, CertTypeEd25519Auth, CertTypeEd25519Identity:
				return nil, fmt.Errorf("failed to parse CERTS entry %d (%s): %w", i, cert.CertType, err)
			default:
				// X.509 / 未知类型：保留原文，由后续校验决定是否硬失败
				cert.X509Cert = nil
				cert.Ed25519Cert = nil
			}
		}

		certs.Certificates = append(certs.Certificates, cert)
	}

	return certs, nil
}

// parseCertificateBody parses the certificate body based on its type
func parseCertificateBody(cert *Certificate) error {
	switch cert.CertType {
	case CertTypeTLSLink, CertTypeRSAID, CertTypeRSAAuth:
		// These are X.509 certificates
		x509Cert, err := x509.ParseCertificate(cert.CertBody)
		if err != nil {
			return fmt.Errorf("failed to parse X.509 certificate type %s: %w", cert.CertType, err)
		}
		cert.X509Cert = x509Cert
		return nil

	case CertTypeEd25519Identity:
		// CERTS type 7 是 RSA→Ed25519 cross-certificate，不是 Ed25519 cert。
		// cert-spec: ED25519_KEY(32) || EXPIRATION(4) || SIGLEN(1) || SIGNATURE
		cross, err := parseRSAEd25519CrossCert(cert.CertBody)
		if err != nil {
			return fmt.Errorf("failed to parse RSA→Ed25519 cross-cert: %w", err)
		}
		cert.Ed25519Cert = cross
		return nil

	case CertTypeEd25519Signing, CertTypeEd25519TLSLink, CertTypeEd25519Auth:
		ed25519Cert, err := parseEd25519Certificate(cert.CertBody)
		if err != nil {
			return fmt.Errorf("failed to parse Ed25519 certificate type %s: %w", cert.CertType, err)
		}
		cert.Ed25519Cert = ed25519Cert
		return nil

	default:
		// Unknown certificate type - store body but don't parse
		return fmt.Errorf("unknown certificate type: %d", cert.CertType)
	}
}

func parseRSAEd25519CrossCert(data []byte) (*Ed25519Certificate, error) {
	if len(data) < 37 {
		return nil, fmt.Errorf("cross-cert too short: %d", len(data))
	}
	sigLen := int(data[36])
	if len(data) < 37+sigLen {
		return nil, fmt.Errorf("cross-cert truncated: need %d, have %d", 37+sigLen, len(data))
	}
	hours := binary.BigEndian.Uint32(data[32:36])
	key := make([]byte, 32)
	copy(key, data[0:32])
	sig := make([]byte, sigLen)
	copy(sig, data[37:37+sigLen])
	return &Ed25519Certificate{
		CertType:     7,
		ExpiresAt:    time.Unix(int64(hours)*3600, 0).UTC(),
		CertifiedKey: key,
		Signature:    sig,
		// KEY || EXPIRATION。C Tor 不把 SIGLEN 纳入哈希。
		SignedBytes: append([]byte(nil), data[:rsaEd25519CrossCertSignedLen]...),
	}, nil
}

// parseEd25519Certificate 按 cert-spec / Arti tor-cert 解析 Ed25519 证书。
//
// 扩展编码（ExtLen 只含 ExtData，不含 ExtType/ExtFlags）：
//
//	ExtLen   [2]  = len(ExtData)
//	ExtType  [1]
//	ExtFlags [1]
//	ExtData  [ExtLen]
//
// signed-with-ed25519-key（type 04）的 ExtLen 必须为 32。
// 签名覆盖 PREFIX 之外的全部前置字段；现行 cert-spec 明确没有 prefix 字符串。
func parseEd25519Certificate(data []byte) (*Ed25519Certificate, error) {
	if len(data) < 40 { // Version+Type+Exp+KeyType+Key+N_EXT，尚无签名
		return nil, fmt.Errorf("Ed25519 certificate too short: %d bytes", len(data))
	}

	cert := &Ed25519Certificate{}
	offset := 0

	cert.Version = data[offset]
	offset++
	if cert.Version != 1 {
		return nil, fmt.Errorf("unsupported Ed25519 certificate version: %d", cert.Version)
	}

	cert.CertType = data[offset]
	offset++

	expirationHours := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	cert.ExpiresAt = time.Unix(int64(expirationHours)*3600, 0).UTC()

	cert.CertKeyType = data[offset]
	offset++

	if offset+32 > len(data) {
		return nil, fmt.Errorf("truncated certified key at offset %d", offset)
	}
	cert.CertifiedKey = make([]byte, 32)
	copy(cert.CertifiedKey, data[offset:offset+32])
	offset += 32

	if offset >= len(data) {
		return nil, fmt.Errorf("truncated extension count at offset %d", offset)
	}
	numExtensions := int(data[offset])
	offset++

	cert.Extensions = make([]Ed25519Extension, 0, numExtensions)
	for i := 0; i < numExtensions; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated extension header at offset %d", offset)
		}
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+2+extLen > len(data) {
			return nil, fmt.Errorf("truncated extension data: ExtLen=%d at offset %d", extLen, offset)
		}
		ext := Ed25519Extension{
			ExtType: data[offset],
			Flags:   data[offset+1],
			ExtData: make([]byte, extLen),
		}
		copy(ext.ExtData, data[offset+2:offset+2+extLen])
		offset += 2 + extLen
		cert.Extensions = append(cert.Extensions, ext)
	}

	if offset+64 > len(data) {
		return nil, fmt.Errorf("truncated signature at offset %d", offset)
	}
	if offset+64 != len(data) {
		return nil, fmt.Errorf("Ed25519 certificate has %d trailing bytes after signature", len(data)-offset-64)
	}
	cert.SignedBytes = append([]byte(nil), data[:offset]...)
	cert.Signature = make([]byte, 64)
	copy(cert.Signature, data[offset:offset+64])

	return cert, nil
}

// SignedWithEd25519Key 返回 signed-with-ed25519-key 扩展中的公钥（若存在）。
func (e *Ed25519Certificate) SignedWithEd25519Key() []byte {
	if e == nil {
		return nil
	}
	for _, ext := range e.Extensions {
		if ext.ExtType == ExtTypeSignedWithEd25519Key && len(ext.ExtData) == ed25519.PublicKeySize {
			return ext.ExtData
		}
	}
	return nil
}

// FindCertificate finds a certificate of the given type in the CERTS cell
func (c *CERTSCell) FindCertificate(certType CertType) *Certificate {
	for _, cert := range c.Certificates {
		if cert.CertType == certType {
			return cert
		}
	}
	return nil
}

// ValidateRelayIdentity validates the relay identity using CERTS cell
// This verifies that the relay's claimed identity matches the certificates
// Per tor-spec.txt §4.2, we need:
//  1. RSA identity key certificate (type 2)
//  2. Ed25519 identity key certificate (type 4 or 7)
func (c *CERTSCell) ValidateRelayIdentity(expectedRSAFingerprint string, expectedEd25519Identity []byte) error {
	// Check for RSA identity certificate if fingerprint provided
	if expectedRSAFingerprint != "" {
		rsaCert := c.FindCertificate(CertTypeRSAID)
		if rsaCert == nil || rsaCert.X509Cert == nil {
			return fmt.Errorf("missing RSA identity certificate")
		}

		// Verify RSA fingerprint
		rsaPubKey, ok := rsaCert.X509Cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA identity cert does not contain RSA public key")
		}

		// Calculate fingerprint (SHA-1 hash of RSA public key in PKCS#1 DER encoding)
		derBytes := x509.MarshalPKCS1PublicKey(rsaPubKey)

		// For Tor, we use SHA-1 of the DER encoding per dir-spec.txt
		// The relay fingerprint is the SHA-1 hash of the DER-encoded RSA public key
		fingerprint := sha1.Sum(derBytes)                   // #nosec G401 - SHA-1 required by Tor spec for RSA fingerprints
		fingerprintHex := fmt.Sprintf("%X", fingerprint[:]) // All 20 bytes of SHA-1

		if fingerprintHex != expectedRSAFingerprint {
			return fmt.Errorf("RSA identity mismatch: expected %s, got %s", expectedRSAFingerprint, fingerprintHex)
		}
	}

	if len(expectedEd25519Identity) > 0 {
		if len(expectedEd25519Identity) != 32 {
			return fmt.Errorf("invalid expected Ed25519 identity length: %d", len(expectedEd25519Identity))
		}
		identityKey, err := c.Ed25519IdentityKey()
		if err != nil {
			return err
		}
		if !bytes.Equal(identityKey, expectedEd25519Identity) {
			return fmt.Errorf("Ed25519 identity mismatch")
		}
	}

	return nil
}

// Ed25519IdentityKey 返回 relay 长期 Ed25519 身份公钥。
//
// 来源（按优先级）：
//  1. CERTS type 7 RSA→Ed25519 cross-cert 的 ED25519_KEY
//  2. type 4 的 signed-with-ed25519-key 扩展
//
// type 4 的 CertifiedKey 是中期 signing key，不是 identity。
func (c *CERTSCell) Ed25519IdentityKey() ([]byte, error) {
	if type7 := c.FindCertificate(CertTypeEd25519Identity); type7 != nil && type7.Ed25519Cert != nil {
		key := type7.Ed25519Cert.CertifiedKey
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid Ed25519 certified key length: %d", len(key))
		}
		return key, nil
	}
	if type4 := c.FindCertificate(CertTypeEd25519Signing); type4 != nil && type4.Ed25519Cert != nil {
		if key := type4.Ed25519Cert.SignedWithEd25519Key(); len(key) == 32 {
			return key, nil
		}
	}
	return nil, fmt.Errorf("missing Ed25519 identity certificate")
}

// ValidateExpiration checks if any certificates in the CERTS cell have expired
func (c *CERTSCell) ValidateExpiration() error {
	now := time.Now()

	for _, cert := range c.Certificates {
		if cert.X509Cert != nil {
			if now.After(cert.X509Cert.NotAfter) {
				return fmt.Errorf("X.509 certificate type %s expired at %v", cert.CertType, cert.X509Cert.NotAfter)
			}
			if now.Before(cert.X509Cert.NotBefore) {
				return fmt.Errorf("X.509 certificate type %s not yet valid (valid from %v)", cert.CertType, cert.X509Cert.NotBefore)
			}
		}

		if cert.Ed25519Cert != nil {
			if now.After(cert.Ed25519Cert.ExpiresAt) {
				return fmt.Errorf("Ed25519 certificate type %s expired at %v", cert.CertType, cert.Ed25519Cert.ExpiresAt)
			}
		}
	}

	return nil
}

// VerifySignature 按 cert-spec 验证 Ed25519 证书签名。
// 签名覆盖证书在 SIGNATURE 之前的全部字段，没有 prefix 字符串
// （见 spec：「this signature is not personalized with a prefix string」）。
//
// signingKey 必须是实际签名公钥。type 4 由长期 identity 签名，不是 self-signed。
// 若存在 signed-with-ed25519-key 扩展，其公钥必须与 signingKey 一致。
func (e *Ed25519Certificate) VerifySignature(signingKey []byte) error {
	if len(signingKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signing key length: %d, expected %d", len(signingKey), ed25519.PublicKeySize)
	}

	if len(e.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d, expected %d", len(e.Signature), ed25519.SignatureSize)
	}

	if extKey := e.SignedWithEd25519Key(); extKey != nil && !bytes.Equal(extKey, signingKey) {
		return fmt.Errorf("signed-with-ed25519-key extension does not match verification key")
	}

	signedData := e.signedMessage()
	if !ed25519.Verify(ed25519.PublicKey(signingKey), signedData, e.Signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

func (e *Ed25519Certificate) signedMessage() []byte {
	if len(e.SignedBytes) > 0 {
		return e.SignedBytes
	}
	return e.reconstructSignedBytes()
}

func (e *Ed25519Certificate) reconstructSignedBytes() []byte {
	signedData := make([]byte, 0, 256)
	signedData = append(signedData, e.Version)
	signedData = append(signedData, e.CertType)

	expirationHours := uint32(e.ExpiresAt.Unix() / 3600)
	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, expirationHours)
	signedData = append(signedData, expBytes...)

	signedData = append(signedData, e.CertKeyType)
	signedData = append(signedData, e.CertifiedKey...)
	signedData = append(signedData, byte(len(e.Extensions)))

	for _, ext := range e.Extensions {
		// ExtLen = len(ExtData)，与 cert-spec / Arti encode.rs 一致
		extLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(extLenBytes, uint16(len(ext.ExtData)))
		signedData = append(signedData, extLenBytes...)
		signedData = append(signedData, ext.ExtType)
		signedData = append(signedData, ext.Flags)
		signedData = append(signedData, ext.ExtData...)
	}
	return signedData
}

// EncodeEd25519Certificate 按 cert-spec 编码（测试与向量生成用）。
func EncodeEd25519Certificate(cert *Ed25519Certificate) []byte {
	body := cert.signedMessage()
	out := make([]byte, 0, len(body)+len(cert.Signature))
	out = append(out, body...)
	out = append(out, cert.Signature...)
	return out
}

// verifyType7RSACrossCert 用 type 2 遗留 RSA 公钥校验 type 7，
// 把现代 Ed25519 主身份绑到共识仍在使用的 RSA 指纹。
//
// 没有这条绑定，攻击者可保留真实 type 2（指纹匹配共识）同时替换 Ed25519 identity。
func (c *CERTSCell) verifyType7RSACrossCert() error {
	type7 := c.FindCertificate(CertTypeEd25519Identity)
	if type7 == nil {
		return nil
	}
	if type7.Ed25519Cert == nil {
		return fmt.Errorf("type 7 RSA→Ed25519 cross-cert was present but not parsed")
	}

	type2 := c.FindCertificate(CertTypeRSAID)
	if type2 == nil || type2.X509Cert == nil {
		return fmt.Errorf("type 7 RSA→Ed25519 cross-cert requires type 2 RSA identity certificate")
	}
	rsaPub, ok := type2.X509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("type 2 certificate does not contain RSA public key")
	}
	if err := verifyRSAEd25519CrossCert(type7.Ed25519Cert, rsaPub); err != nil {
		return fmt.Errorf("type 7 RSA→Ed25519 cross-cert verification failed: %w", err)
	}
	return nil
}

func verifyRSAEd25519CrossCert(cross *Ed25519Certificate, rsaPub *rsa.PublicKey) error {
	if cross == nil || rsaPub == nil {
		return fmt.Errorf("missing cross-cert or RSA identity key")
	}
	if len(cross.CertifiedKey) != 32 {
		return fmt.Errorf("invalid Ed25519 identity length: %d", len(cross.CertifiedKey))
	}
	if len(cross.Signature) < 128 {
		return fmt.Errorf("RSA signature too short: %d", len(cross.Signature))
	}

	fields := cross.SignedBytes
	if len(fields) == 0 {
		fields = reconstructRSAEd25519CrossCertFields(cross)
	}
	if len(fields) != rsaEd25519CrossCertSignedLen {
		return fmt.Errorf("invalid type 7 signed fields length: %d", len(fields))
	}

	msg := make([]byte, 0, len(rsaEd25519CrossCertPrefix)+len(fields))
	msg = append(msg, rsaEd25519CrossCertPrefix...)
	msg = append(msg, fields...)
	digest := sha256.Sum256(msg)
	if err := rsa.VerifyPKCS1v15(rsaPub, 0, digest[:], cross.Signature); err != nil {
		return err
	}
	return nil
}

func reconstructRSAEd25519CrossCertFields(cross *Ed25519Certificate) []byte {
	if cross == nil || len(cross.CertifiedKey) != 32 {
		return nil
	}
	fields := make([]byte, 0, rsaEd25519CrossCertSignedLen)
	fields = append(fields, cross.CertifiedKey...)
	exp := make([]byte, 4)
	binary.BigEndian.PutUint32(exp, uint32(cross.ExpiresAt.Unix()/3600))
	fields = append(fields, exp...)
	return fields
}

// ValidateSignatures 校验 CERTS 证书链。
//
// 现代身份链：type 7 给出 Ed25519 主身份，type 4/5/6 由 Ed25519 签名。
// 遗留绑定：type 7 本身必须由 type 2 RSA 做 PKCS#1 交叉签名，才能与共识指纹对齐。
func (c *CERTSCell) ValidateSignatures() error {
	if err := c.verifyType7RSACrossCert(); err != nil {
		return err
	}

	for _, cert := range c.Certificates {
		switch cert.CertType {
		case CertTypeEd25519Signing, CertTypeEd25519TLSLink, CertTypeEd25519Auth:
			if cert.Ed25519Cert == nil {
				return fmt.Errorf("%s certificate was present but not parsed", cert.CertType)
			}
		}
		if cert.Ed25519Cert == nil {
			continue
		}

		switch cert.CertType {
		case CertTypeEd25519Signing:
			// Type 4: Ed25519 signing key certificate
			// Per cert-spec.txt, this must be signed by the relay's long-term Ed25519 identity key.
			// The identity key is contained in the type-7 (Ed25519Identity) certificate.
			// Absence of a type-7 cert is a hard error: accepting a self-signed type-4 cert would
			// break the identity binding required by the spec.
			identityCert := c.FindCertificate(CertTypeEd25519Identity)
			if identityCert == nil || identityCert.Ed25519Cert == nil {
				return fmt.Errorf("type 7 (Ed25519 identity) certificate is required to verify type 4 (Ed25519 signing key) but was not found")
			}

			// Extract the Ed25519 identity key from the type-7 certificate
			identityKey := identityCert.Ed25519Cert.CertifiedKey
			if len(identityKey) != 32 {
				return fmt.Errorf("type 7 (Ed25519 identity) certified key has invalid length: %d", len(identityKey))
			}

			// Verify type-4 signature against the identity key
			if err := cert.Ed25519Cert.VerifySignature(identityKey); err != nil {
				return fmt.Errorf("type 4 (Ed25519 signing key) signature verification failed against identity key: %w", err)
			}

		case CertTypeEd25519TLSLink:
			// Type 5: Ed25519 TLS link certificate
			// Signed by the Ed25519 signing key (type 4)
			signingKeyCert := c.FindCertificate(CertTypeEd25519Signing)
			if signingKeyCert == nil || signingKeyCert.Ed25519Cert == nil {
				return fmt.Errorf("type 5 (Ed25519 TLS link) requires type 4 signing key cert")
			}
			if err := cert.Ed25519Cert.VerifySignature(signingKeyCert.Ed25519Cert.CertifiedKey); err != nil {
				return fmt.Errorf("type 5 (Ed25519 TLS link) signature verification failed: %w", err)
			}

		case CertTypeEd25519Auth:
			// Type 6: Ed25519 authentication certificate
			// Signed by the Ed25519 signing key (type 4)
			signingKeyCert := c.FindCertificate(CertTypeEd25519Signing)
			if signingKeyCert == nil || signingKeyCert.Ed25519Cert == nil {
				return fmt.Errorf("type 6 (Ed25519 auth) requires type 4 signing key cert")
			}
			if err := cert.Ed25519Cert.VerifySignature(signingKeyCert.Ed25519Cert.CertifiedKey); err != nil {
				return fmt.Errorf("type 6 (Ed25519 auth) signature verification failed: %w", err)
			}
		}
	}

	return nil
}
