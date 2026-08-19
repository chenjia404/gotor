// Package onion — 致盲私钥签名（rend-spec-v3 KEYBLIND + RFC8032）。
package onion

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// BlindedSigningMaterial 周期致盲后的扩展私钥材料。
type BlindedSigningMaterial struct {
	Scalar    *edwards25519.Scalar
	Prefix    [32]byte
	PublicKey ed25519.PublicKey // A'
}

// DeriveBlindedSigningMaterial 从身份私钥推导当前周期致盲签名材料。
func DeriveBlindedSigningMaterial(identityPriv ed25519.PrivateKey, timePeriod uint64) (*BlindedSigningMaterial, error) {
	if len(identityPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity private key length")
	}
	pub := identityPriv.Public().(ed25519.PublicKey)
	seed := identityPriv.Seed()
	h := sha512.Sum512(seed)
	a, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, err
	}
	var prefix [32]byte
	copy(prefix[:], h[32:])

	param, err := BuildBlindedKeyParam([]byte(pub), nil, timePeriod, hsdirIntervalDefaultMinutes)
	if err != nil {
		return nil, err
	}
	tweak, err := new(edwards25519.Scalar).SetBytesWithClamping(param)
	if err != nil {
		return nil, err
	}
	aPrime := new(edwards25519.Scalar).Multiply(a, tweak)

	// 致盲 nonce 前缀（与验证无关，但避免跨周期 nonce 复用）
	ph := sha512.Sum512(append(append([]byte{}, param...), prefix[:]...))
	copy(prefix[:], ph[:32])

	return &BlindedSigningMaterial{
		Scalar:    aPrime,
		Prefix:    prefix,
		PublicKey: ed25519.PublicKey(ComputeBlindedPubkey(pub, timePeriod)),
	}, nil
}

// Sign 使用致盲标量按 RFC8032 签名。
func (m *BlindedSigningMaterial) Sign(message []byte) ([]byte, error) {
	if m == nil || m.Scalar == nil || len(m.PublicKey) != 32 {
		return nil, fmt.Errorf("invalid blinded signing material")
	}
	hr := sha512.New()
	_, _ = hr.Write(m.Prefix[:])
	_, _ = hr.Write(message)
	rDigest := hr.Sum(nil)
	r, err := edwards25519.NewScalar().SetUniformBytes(rDigest)
	if err != nil {
		return nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(r)

	hk := sha512.New()
	_, _ = hk.Write(R.Bytes())
	_, _ = hk.Write(m.PublicKey)
	_, _ = hk.Write(message)
	kDigest := hk.Sum(nil)
	k, err := edwards25519.NewScalar().SetUniformBytes(kDigest)
	if err != nil {
		return nil, err
	}
	S := edwards25519.NewScalar().MultiplyAdd(k, m.Scalar, r)
	sig := make([]byte, 64)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig, nil
}
