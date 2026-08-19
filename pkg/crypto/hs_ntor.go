// Package crypto — hs-ntor（rend-spec-v3 NTOR-WITH-EXTRA-DATA）。
//
// 对照：
//   - https://spec.torproject.org/rend-spec/introduction-handshake.html
//   - https://spec.torproject.org/rend-spec/rendezvous-protocol.html
//   - C Tor src/core/crypto/hs_ntor.c
//   - Arti tor-proto hs_ntor / tor-hscrypto ops::hs_mac
//
// MAC(k,m) = SHA3-256(htonll(len(k)) || k || m)
// KDF 为 SHAKE-256（crypto_xof）。
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const (
	hsNtorProtoID   = "tor-hs-ntor-curve25519-sha3-256-1"
	hsNtorTHsEnc    = hsNtorProtoID + ":hs_key_extract"
	hsNtorTHsVerify = hsNtorProtoID + ":hs_verify"
	hsNtorTHsMac    = hsNtorProtoID + ":hs_mac"
	hsNtorMExpand   = hsNtorProtoID + ":hs_key_expand"
	hsNtorServerStr = "Server"

	HsNtorEncKeyLen     = 32
	HsNtorMacKeyLen     = 32
	HsNtorAuthMacLen    = 32
	HsNtorKeySeedLen    = 32
	HsNtorSubcredLen    = 32
	HsNtorAuthKeyLen    = 32                // Ed25519 intro auth pubkey
	HsNtorResponseLen   = 64                // Y(32) || AUTH_INPUT_MAC(32)
	HsNtorCircuitKeyLen = 32 + 32 + 32 + 32 // Df||Db||Kf||Kb（各 SHA3-256 / AES-256）
)

// HsMAC 实现 rend-spec MAC：SHA3-256(htonll(len(key)) || key || msg)。
func HsMAC(key, msg []byte) []byte {
	h := sha3.New256()
	var klen [8]byte
	binary.BigEndian.PutUint64(klen[:], uint64(len(key)))
	_, _ = h.Write(klen[:])
	_, _ = h.Write(key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func hsShake(out []byte, input []byte) {
	sha3.ShakeSum256(out, input)
}

func curve25519Shared(priv, pub []byte) ([]byte, error) {
	if len(priv) != 32 || len(pub) != 32 {
		return nil, fmt.Errorf("hs-ntor: bad curve25519 key length")
	}
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, err
	}
	if isAllZero(out) {
		return nil, fmt.Errorf("hs-ntor: degenerate shared secret")
	}
	return out, nil
}

// HsNtorClientIntroKeys 客户端计算 INTRODUCE1 加密用 ENC_KEY / MAC_KEY。
//
//	intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
//	info = m_hsexpand | subcredential
//	hs_keys = SHAKE256(intro_secret_hs_input | t_hsenc | info)
func HsNtorClientIntroKeys(xPriv, B, authKey, subcred []byte) (encKey, macKey, X []byte, err error) {
	if len(xPriv) != 32 || len(B) != 32 || len(authKey) != HsNtorAuthKeyLen || len(subcred) != HsNtorSubcredLen {
		return nil, nil, nil, fmt.Errorf("hs-ntor: invalid intro key lengths")
	}
	X, err = curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, err
	}
	bx, err := curve25519Shared(xPriv, B)
	if err != nil {
		return nil, nil, nil, err
	}
	secret := make([]byte, 0, 32+32+32+32+len(hsNtorProtoID))
	secret = append(secret, bx...)
	secret = append(secret, authKey...)
	secret = append(secret, X...)
	secret = append(secret, B...)
	secret = append(secret, hsNtorProtoID...)

	info := append([]byte(hsNtorMExpand), subcred...)
	kdfIn := make([]byte, 0, len(secret)+len(hsNtorTHsEnc)+len(info))
	kdfIn = append(kdfIn, secret...)
	kdfIn = append(kdfIn, hsNtorTHsEnc...)
	kdfIn = append(kdfIn, info...)

	keys := make([]byte, HsNtorEncKeyLen+HsNtorMacKeyLen)
	hsShake(keys, kdfIn)
	return keys[:HsNtorEncKeyLen], keys[HsNtorEncKeyLen:], X, nil
}

// HsNtorServiceIntroKeys 服务端用 bPriv 与客户端 X 推导 INTRODUCE2 解密密钥。
//
//	intro_secret_hs_input = EXP(X,b) | AUTH_KEY | X | B | PROTOID
func HsNtorServiceIntroKeys(bPriv, X, authKey, subcred []byte) (encKey, macKey, B []byte, err error) {
	if len(bPriv) != 32 || len(X) != 32 || len(authKey) != HsNtorAuthKeyLen || len(subcred) != HsNtorSubcredLen {
		return nil, nil, nil, fmt.Errorf("hs-ntor: invalid service intro key lengths")
	}
	B, err = curve25519.X25519(bPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, err
	}
	xb, err := curve25519Shared(bPriv, X)
	if err != nil {
		return nil, nil, nil, err
	}
	secret := make([]byte, 0, 32+32+32+32+len(hsNtorProtoID))
	secret = append(secret, xb...)
	secret = append(secret, authKey...)
	secret = append(secret, X...)
	secret = append(secret, B...)
	secret = append(secret, hsNtorProtoID...)

	info := append([]byte(hsNtorMExpand), subcred...)
	kdfIn := make([]byte, 0, len(secret)+len(hsNtorTHsEnc)+len(info))
	kdfIn = append(kdfIn, secret...)
	kdfIn = append(kdfIn, hsNtorTHsEnc...)
	kdfIn = append(kdfIn, info...)

	keys := make([]byte, HsNtorEncKeyLen+HsNtorMacKeyLen)
	hsShake(keys, kdfIn)
	return keys[:HsNtorEncKeyLen], keys[HsNtorEncKeyLen:], B, nil
}

// HsNtorServiceRend 服务端完成 RENDEZVOUS1：输出 Y||AUTH 与 NTOR_KEY_SEED。
//
//	rend_secret_hs_input = EXP(X,y) | EXP(X,b) | AUTH_KEY | B | X | Y | PROTOID
func HsNtorServiceRend(yPriv, bPriv, X, authKey []byte) (response, ntorKeySeed []byte, err error) {
	if len(yPriv) != 32 || len(bPriv) != 32 || len(X) != 32 || len(authKey) != HsNtorAuthKeyLen {
		return nil, nil, fmt.Errorf("hs-ntor: invalid service rend key lengths")
	}
	Y, err := curve25519.X25519(yPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	B, err := curve25519.X25519(bPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	xy, err := curve25519Shared(yPriv, X)
	if err != nil {
		return nil, nil, err
	}
	xb, err := curve25519Shared(bPriv, X)
	if err != nil {
		return nil, nil, err
	}
	seed, authMAC, err := hsNtorRendFinish(xy, xb, authKey, B, X, Y)
	if err != nil {
		return nil, nil, err
	}
	resp := make([]byte, HsNtorResponseLen)
	copy(resp[:32], Y)
	copy(resp[32:], authMAC)
	return resp, seed, nil
}

// HsNtorClientRend 客户端验证 RENDEZVOUS2 并得到 NTOR_KEY_SEED。
//
//	rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
func HsNtorClientRend(xPriv, B, authKey, response []byte) (ntorKeySeed []byte, err error) {
	if len(xPriv) != 32 || len(B) != 32 || len(authKey) != HsNtorAuthKeyLen || len(response) != HsNtorResponseLen {
		return nil, fmt.Errorf("hs-ntor: invalid client rend lengths")
	}
	Y := response[:32]
	gotAuth := response[32:]
	X, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	yx, err := curve25519Shared(xPriv, Y)
	if err != nil {
		return nil, err
	}
	bx, err := curve25519Shared(xPriv, B)
	if err != nil {
		return nil, err
	}
	seed, authMAC, err := hsNtorRendFinish(yx, bx, authKey, B, X, Y)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(authMAC, gotAuth) != 1 {
		return nil, fmt.Errorf("hs-ntor: AUTH_INPUT_MAC mismatch")
	}
	return seed, nil
}

func hsNtorRendFinish(dh1, dh2, authKey, B, X, Y []byte) (ntorKeySeed, authMAC []byte, err error) {
	secret := make([]byte, 0, 32+32+32+32+32+32+len(hsNtorProtoID))
	secret = append(secret, dh1...)
	secret = append(secret, dh2...)
	secret = append(secret, authKey...)
	secret = append(secret, B...)
	secret = append(secret, X...)
	secret = append(secret, Y...)
	secret = append(secret, hsNtorProtoID...)

	ntorKeySeed = HsMAC(secret, []byte(hsNtorTHsEnc))
	verify := HsMAC(secret, []byte(hsNtorTHsVerify))

	authInput := make([]byte, 0, 32+32+32+32+32+len(hsNtorProtoID)+len(hsNtorServerStr))
	authInput = append(authInput, verify...)
	authInput = append(authInput, authKey...)
	authInput = append(authInput, B...)
	authInput = append(authInput, Y...)
	authInput = append(authInput, X...)
	authInput = append(authInput, hsNtorProtoID...)
	authInput = append(authInput, hsNtorServerStr...)
	authMAC = HsMAC(authInput, []byte(hsNtorTHsMac))
	return ntorKeySeed, authMAC, nil
}

// HsNtorExpandCircuitKeys 从 NTOR_KEY_SEED 展开电路密钥材料。
//
//	K = SHAKE256(NTOR_KEY_SEED | m_hsexpand)
//
// 输出 Df(32) || Db(32) || Kf(32) || Kb(32)。
func HsNtorExpandCircuitKeys(ntorKeySeed []byte) ([]byte, error) {
	if len(ntorKeySeed) != HsNtorKeySeedLen {
		return nil, fmt.Errorf("hs-ntor: bad key seed length")
	}
	in := append(append([]byte{}, ntorKeySeed...), hsNtorMExpand...)
	out := make([]byte, HsNtorCircuitKeyLen)
	hsShake(out, in)
	return out, nil
}

// GenerateCurve25519PrivateKey 生成可用的 Curve25519 私钥（32 字节，已 clamp）。
func GenerateCurve25519PrivateKey() ([]byte, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	out := make([]byte, 32)
	copy(out, priv[:])
	return out, nil
}
