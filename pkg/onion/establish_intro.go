// Package onion — ESTABLISH_INTRO / INTRO_ESTABLISHED（rend-spec-v3 §3.1.1）。
package onion

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/binary"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

const (
	establishIntroPrefix = "Tor establish-intro cell v1"
	introAuthKeyTypeEd   = 0x02
	introMACLen          = 32 // SHA3-256
)

// EstablishIntroKeys 引言点侧 AUTH_KEY（Ed25519）与 ENC_KEY（Curve25519 私钥）。
type EstablishIntroKeys struct {
	AuthPrivate ed25519.PrivateKey // 64 字节
	AuthPublic  ed25519.PublicKey  // 32 字节
	EncPrivate  []byte             // 32 字节 Curve25519
}

// GenerateEstablishIntroKeys 生成合法引言点密钥对。
func GenerateEstablishIntroKeys() (*EstablishIntroKeys, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	encPriv, err := generateCurve25519Private()
	if err != nil {
		return nil, err
	}
	return &EstablishIntroKeys{
		AuthPrivate: priv,
		AuthPublic:  pub,
		EncPrivate:  encPriv,
	}, nil
}

func generateCurve25519Private() ([]byte, error) {
	return crypto.GenerateCurve25519PrivateKey()
}

// BuildEstablishIntroPayload 构造 ESTABLISH_INTRO 载荷（不含 RELAY 头）。
//
//	AUTH_KEY_TYPE [1] = 0x02
//	AUTH_KEY_LEN  [2]
//	AUTH_KEY      [32]
//	N_EXTENSIONS  [1]
//	HANDSHAKE_AUTH [32]  = SHA3-256-MAC(key=circ_nonce[20], msg=上述字段)
//	SIG_LEN       [2]
//	SIG           [64]   = Ed25519(AUTH_KEY_priv, "Tor establish-intro cell v1" || 上述至 SIG_LEN 之前)
func BuildEstablishIntroPayload(authPub ed25519.PublicKey, authPriv ed25519.PrivateKey, circNonce []byte) ([]byte, error) {
	if len(authPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth public key length %d", len(authPub))
	}
	if len(authPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("auth private key length %d", len(authPriv))
	}
	if len(circNonce) != 20 {
		return nil, fmt.Errorf("circ_nonce length %d, want 20", len(circNonce))
	}

	body := make([]byte, 0, 1+2+32+1+introMACLen+2+64)
	body = append(body, introAuthKeyTypeEd)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, 32)
	body = append(body, lenBuf...)
	body = append(body, authPub...)
	body = append(body, 0) // N_EXTENSIONS

	mac := sha3MAC(circNonce, body)
	body = append(body, mac...)

	signMsg := append([]byte(establishIntroPrefix), body...)
	sig := ed25519.Sign(authPriv, signMsg)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(sig)))
	body = append(body, lenBuf...)
	body = append(body, sig...)
	return body, nil
}

// VerifyEstablishIntroPayload 校验（测试 / 调试用）。
func VerifyEstablishIntroPayload(payload, circNonce []byte) error {
	if len(payload) < 1+2+32+1+introMACLen+2+64 {
		return fmt.Errorf("ESTABLISH_INTRO too short: %d", len(payload))
	}
	if payload[0] != introAuthKeyTypeEd {
		return fmt.Errorf("AUTH_KEY_TYPE %d, want 0x02", payload[0])
	}
	authLen := binary.BigEndian.Uint16(payload[1:3])
	if authLen != 32 {
		return fmt.Errorf("AUTH_KEY_LEN %d", authLen)
	}
	authPub := ed25519.PublicKey(payload[3:35])
	off := 35
	nExt := int(payload[off])
	off++
	for i := 0; i < nExt; i++ {
		if off+2 > len(payload) {
			return fmt.Errorf("truncated extensions")
		}
		extLen := int(payload[off+1])
		off += 2 + extLen
	}
	macStart := off
	macEnd := off + introMACLen
	if macEnd > len(payload) {
		return fmt.Errorf("truncated MAC")
	}
	expectedMAC := sha3MAC(circNonce, payload[:macStart])
	gotMAC := payload[macStart:macEnd]
	if subtleConstantTimeCompare(expectedMAC, gotMAC) != 1 {
		return fmt.Errorf("HANDSHAKE_AUTH MAC mismatch")
	}
	sigLenOff := macEnd
	if sigLenOff+2 > len(payload) {
		return fmt.Errorf("truncated SIG_LEN")
	}
	sigLen := int(binary.BigEndian.Uint16(payload[sigLenOff : sigLenOff+2]))
	sigOff := sigLenOff + 2
	if sigOff+sigLen > len(payload) || sigLen != ed25519.SignatureSize {
		return fmt.Errorf("bad SIG_LEN %d", sigLen)
	}
	sig := payload[sigOff : sigOff+sigLen]
	signed := append([]byte(establishIntroPrefix), payload[:sigLenOff]...)
	if !ed25519.Verify(authPub, signed, sig) {
		return fmt.Errorf("ESTABLISH_INTRO signature invalid")
	}
	return nil
}

func sha3MAC(key, msg []byte) []byte {
	return sha3MacSHA256Ctor(key, msg)
}

// sha3MacSHA256Ctor 对照 C Tor crypto_mac_sha3_256：
//
//	SHA3-256( uint64_be(key_len) || key || msg )
func sha3MacSHA256Ctor(key, msg []byte) []byte {
	h := sha3.New256()
	var lenBE [8]byte
	binary.BigEndian.PutUint64(lenBE[:], uint64(len(key)))
	_, _ = h.Write(lenBE[:])
	_, _ = h.Write(key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func subtleConstantTimeCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

// NewEstablishIntroRelayCell 封装为 RELAY cell。
func NewEstablishIntroRelayCell(payload []byte) (*cell.RelayCell, error) {
	return cell.NewRelayCell(0, cell.RelayEstablishIntro, payload)
}
