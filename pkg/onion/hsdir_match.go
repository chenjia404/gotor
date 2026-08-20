package onion

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

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
		RevisionCounter: 1,
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
