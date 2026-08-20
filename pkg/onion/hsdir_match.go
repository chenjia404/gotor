package onion

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"
)

// VerifyHSDirOuterDescriptor 校验 HSDir 外层：type-8 证书未过期、由致盲公钥签发，
// 且描述符正文由证书内 signing key 签名。HSDir 没有洋葱主身份，不能走
// ParseDescriptorWithVerification。未宣告 HSDir=2。
func VerifyHSDirOuterDescriptor(raw []byte) (blinded []byte, revision uint64, canonical []byte, err error) {
	sigIdx := bytes.Index(raw, []byte("signature "))
	if sigIdx < 0 {
		return nil, 0, nil, fmt.Errorf("signature line missing")
	}
	// 只解析签名覆盖范围：签名行之后的 revision-counter 等不得抬高修订号。
	desc, err := ParseDescriptor(raw[:sigIdx])
	if err != nil || desc == nil {
		return nil, 0, nil, fmt.Errorf("parse descriptor")
	}
	sig, err := parseHSDirSignatureLine(raw[sigIdx:])
	if err != nil {
		return nil, 0, nil, err
	}
	if len(desc.DescriptorSigningKeyCert) == 0 {
		return nil, 0, nil, fmt.Errorf("descriptor missing type-8 cert")
	}
	cert, err := parseCertificate(desc.DescriptorSigningKeyCert)
	if err != nil || cert.CertType != 8 {
		return nil, 0, nil, fmt.Errorf("type-8 certificate")
	}
	if time.Now().After(cert.ExpiresAt) {
		return nil, 0, nil, fmt.Errorf("type-8 certificate expired")
	}
	if len(cert.SigningKey) != ed25519.PublicKeySize || len(cert.SignedWithKey) != ed25519.PublicKeySize {
		return nil, 0, nil, fmt.Errorf("type-8 missing certified or signed-with key")
	}
	if !ed25519.Verify(ed25519.PublicKey(cert.SignedWithKey), cert.SignedData, cert.Signature) {
		return nil, 0, nil, fmt.Errorf("type-8 certificate signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(cert.SigningKey), HSDescriptorSignedMaterial(raw[:sigIdx]), sig) {
		return nil, 0, nil, fmt.Errorf("descriptor signature")
	}
	end := len(raw)
	if i := bytes.IndexByte(raw[sigIdx:], '\n'); i >= 0 {
		end = sigIdx + i + 1
	}
	return append([]byte(nil), cert.SignedWithKey...), desc.RevisionCounter, append([]byte(nil), raw[:end]...), nil
}

func parseHSDirSignatureLine(fromSig []byte) ([]byte, error) {
	line := fromSig
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("signature ")))
	line = bytes.TrimSuffix(line, []byte("\r"))
	sig, err := decodeDescriptorBase64(string(line))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("descriptor signature")
	}
	return sig, nil
}

// MatchHSDirDescriptor 若 raw 外层 type-8 证书由 blinded 公钥签发，则本 HSDir 应按该盲化身份提供此文档。
// 中继 HSDir 切片用此把 POST 正文索引到 GET /tor/hs/3/<base64>，不宣称 HSDir=2。
func MatchHSDirDescriptor(raw, blinded []byte) bool {
	if len(blinded) != ed25519.PublicKeySize {
		return false
	}
	desc, err := ParseDescriptor(raw)
	if err != nil || desc == nil || len(desc.DescriptorSigningKeyCert) == 0 {
		return false
	}
	cert, err := parseCertificate(desc.DescriptorSigningKeyCert)
	if err != nil || cert.CertType != 8 {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(blinded), cert.SignedData, cert.Signature)
}

// BuildSignedHSDescriptor 构造带 type-8 证书的 v3 外层文档，供 HSDir 收/服单测。
func BuildSignedHSDescriptor(identity ed25519.PrivateKey) (raw, blinded []byte, err error) {
	return BuildSignedHSDescriptorAtRevision(identity, 1)
}

// BuildSignedHSDescriptorAtRevision 指定 revision-counter。
func BuildSignedHSDescriptorAtRevision(identity ed25519.PrivateKey, revision uint64) (raw, blinded []byte, err error) {
	if len(identity) == 0 {
		return nil, nil, fmt.Errorf("empty identity")
	}
	pub := identity.Public().(ed25519.PublicKey)
	addr := &Address{Pubkey: []byte(pub)}
	blinded = ComputeBlindedPubkey(pub, GetTimePeriod(time.Now()))
	desc := &Descriptor{
		Version:         3,
		Address:         addr,
		BlindedPubkey:   blinded,
		RevisionCounter: revision,
		Lifetime:        3 * time.Hour,
		IntroPoints: []IntroductionPoint{{
			LinkSpecifiers: []LinkSpecifier{{Type: 0, Data: []byte{192, 0, 2, 1, 0, 80}}},
			OnionKey:       make([]byte, 32),
			AuthKey:        make([]byte, 32),
			EncKey:         make([]byte, 32),
		}},
	}
	if err := (&Service{identityKey: identity, address: addr}).signDescriptor(desc); err != nil {
		return nil, nil, err
	}
	return desc.RawDescriptor, blinded, nil
}
