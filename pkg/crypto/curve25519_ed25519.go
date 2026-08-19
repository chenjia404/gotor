// Package crypto — Curve25519 ntor 密钥到 Ed25519 的转换（dir-spec converting-to-ed25519）。
//
// 权威用 ntor 公钥 + 描述符里的 Bit 还原 Ed25519 公钥，再验 ntor-onion-key-crosscert。
// 签名必须用同一把由 ntor 私钥导出的扩展 Ed25519 密钥，否则权威验签失败。
package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/curve25519"
)

// curve25519ToEd25519Prefix 是 C Tor / dir-spec 规定的 NUL 结尾派生串。
// SHA512(clamped_sk || prefix)[0:32] 作为 Ed25519 扩展私钥的 nonce 前缀。
const curve25519ToEd25519Prefix = "Derive high part of ed25519 key from curve25519 key\x00"

// Curve25519Ed25519Keypair 由 ntor（X25519）私钥导出的 Ed25519 签名材料。
type Curve25519Ed25519Keypair struct {
	Public  ed25519.PublicKey
	Scalar  *edwards25519.Scalar
	Prefix  [32]byte
	SignBit int // 0 或 1，写入 ntor-onion-key-crosscert 的 Bit
}

// Ed25519KeypairFromCurve25519 按 dir-spec / C Tor 把 32 字节 ntor 私钥转成 Ed25519 密钥。
func Ed25519KeypairFromCurve25519(ntorPriv []byte) (*Curve25519Ed25519Keypair, error) {
	if len(ntorPriv) != 32 {
		return nil, fmt.Errorf("ntor private key must be 32 bytes, got %d", len(ntorPriv))
	}
	clamped := clampX25519(ntorPriv)
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(clamped)
	if err != nil {
		return nil, fmt.Errorf("ed25519 scalar from ntor key: %w", err)
	}

	h := sha512.New()
	_, _ = h.Write(clamped)
	_, _ = h.Write([]byte(curve25519ToEd25519Prefix))
	sum := h.Sum(nil)

	var prefix [32]byte
	copy(prefix[:], sum[:32])

	pub := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	return &Curve25519Ed25519Keypair{
		Public:  ed25519.PublicKey(append([]byte(nil), pub...)),
		Scalar:  scalar,
		Prefix:  prefix,
		SignBit: int(pub[31] >> 7),
	}, nil
}

// Sign 按 RFC 8032 用扩展私钥签名（标量来自 ntor，不是 SHA512(seed)）。
func (k *Curve25519Ed25519Keypair) Sign(message []byte) ([]byte, error) {
	if k == nil || k.Scalar == nil || len(k.Public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid curve25519-ed25519 keypair")
	}
	hr := sha512.New()
	_, _ = hr.Write(k.Prefix[:])
	_, _ = hr.Write(message)
	r, err := edwards25519.NewScalar().SetUniformBytes(hr.Sum(nil))
	if err != nil {
		return nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(r)

	hk := sha512.New()
	_, _ = hk.Write(R.Bytes())
	_, _ = hk.Write(k.Public)
	_, _ = hk.Write(message)
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(hk.Sum(nil))
	if err != nil {
		return nil, err
	}
	S := edwards25519.NewScalar().MultiplyAdd(kScalar, k.Scalar, r)
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig, nil
}

// Ed25519PublicFromX25519 用 ntor 公钥的 Montgomery u 与 Bit 还原 Ed25519 公钥。
// 权威验 ntor-onion-key-crosscert 走这条路径，必须与私钥导出的公钥一致。
func Ed25519PublicFromX25519(ntorPub []byte, signBit int) (ed25519.PublicKey, error) {
	if len(ntorPub) != 32 {
		return nil, fmt.Errorf("ntor public key must be 32 bytes, got %d", len(ntorPub))
	}
	if signBit != 0 && signBit != 1 {
		return nil, fmt.Errorf("sign bit must be 0 or 1, got %d", signBit)
	}
	var u field.Element
	if _, err := u.SetBytes(ntorPub); err != nil {
		return nil, fmt.Errorf("invalid x25519 public key: %w", err)
	}
	var one field.Element
	one.One()
	var um1, up1, y field.Element
	um1.Subtract(&u, &one)
	up1.Add(&u, &one)
	var up1Inv field.Element
	up1Inv.Invert(&up1)
	y.Multiply(&um1, &up1Inv)
	yb := y.Bytes()
	if signBit == 1 {
		yb[31] |= 0x80
	} else {
		yb[31] &= 0x7f
	}
	return ed25519.PublicKey(yb[:]), nil
}

// X25519PublicFromPrivate 计算 ntor 公钥（与 descriptor 里 ntor-onion-key 一致）。
func X25519PublicFromPrivate(ntorPriv []byte) ([]byte, error) {
	if len(ntorPriv) != 32 {
		return nil, fmt.Errorf("ntor private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(ntorPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func clampX25519(sk []byte) []byte {
	out := make([]byte, 32)
	copy(out, sk)
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}
