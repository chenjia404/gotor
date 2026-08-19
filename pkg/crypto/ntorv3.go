// ntor-v3 握手，对照现行 tor-spec create-created-cells “The ntor-v3 handshake”。
//
// 这是现代 Tor 客户端的默认电路握手（HTYPE 0x0003）。经典 ntor 0x0002
// 仅在没有扩展可发时使用。主身份是 32 字节 Ed25519，不是 RSA-1024。
//
//	PROTOID = "ntor3-curve25519-sha3_256-1"
//	H(s,t)   = SHA3_256(ENCAP(t) | s)
//	MAC(k,m,t) = SHA3_256(ENCAP(t) | ENCAP(k) | m)
//	KDF(s,t) = SHAKE256(ENCAP(t) | s)
//	ENC      = AES-256-CTR，IV 全零（C Tor crypto_cipher_new_with_bits）
//	ENCAP(s) = htonll(len(s)) || s
//	ID_LEN   = 32（KP_relayid_ed）
//
// 电路密钥从 KDF_final 的 KEYSTREAM 取出（跳过 32 字节 ENC_KEY）：
// Df(20) || Db(20) || Kf(16) || Kb(16)。
//
// C Tor: src/core/crypto/onion_ntor_v3.c
// Arti: crates/tor-proto/src/crypto/handshake/ntor_v3.rs
// Spec：https://spec.torproject.org/tor-spec/create-created-cells.html
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const (
	ntorV3ProtoID   = "ntor3-curve25519-sha3_256-1"
	ntorV3TMsgKDF   = ntorV3ProtoID + ":kdf_phase1"
	ntorV3TMsgMAC   = ntorV3ProtoID + ":msg_mac"
	ntorV3TKeySeed  = ntorV3ProtoID + ":key_seed"
	ntorV3TVerify   = ntorV3ProtoID + ":verify"
	ntorV3TFinal    = ntorV3ProtoID + ":kdf_final"
	ntorV3TAuth     = ntorV3ProtoID + ":auth_final"
	ntorV3ServerStr = "Server"

	NtorV3IDLen          = 32
	NtorV3PubLen         = 32
	NtorV3MACLen         = 32
	NtorV3EncKeyLen      = 32
	NtorV3FixedClientLen = NtorV3IDLen + NtorV3PubLen + NtorV3PubLen + NtorV3MACLen // 不含 MSG
	NtorV3FixedServerLen = NtorV3PubLen + NtorV3MACLen                              // 不含 MSG
	NtorV3KeyMaterialLen = 72
)

// NtorV3CircuitVerification 是电路 CREATE2/EXTEND2 的 verification。
// C Tor onion_crypto.c / Arti ntor_v3.rs：`NTOR3_CIRC_VERIFICATION = "circuit extend"`。
var NtorV3CircuitVerification = []byte("circuit extend")

// NtorV3ExtType 是握手加密附加数据里的扩展类型。
const (
	NtorV3ExtCCRequest       uint8 = 1
	NtorV3ExtCCResponse      uint8 = 2
	NtorV3ExtSubprotoRequest uint8 = 3 // proposal 346 / RELAY_NEGOTIATE_SUBPROTO
)

// NtorV3Extension 是 ntor-v3 CM/SM 里的一条扩展。
type NtorV3Extension struct {
	Type uint8
	Data []byte
}

// NtorV3ClientState 保存客户端第一阶段状态，供处理 CREATED2/EXTENDED2。
type NtorV3ClientState struct {
	x      [32]byte
	X      [32]byte
	B      [32]byte
	ID     []byte
	Bx     [32]byte
	msgMAC []byte
}

func ntorV3Encap(s []byte) []byte {
	out := make([]byte, 8+len(s))
	binary.BigEndian.PutUint64(out[:8], uint64(len(s)))
	copy(out[8:], s)
	return out
}

func ntorV3Hash(t string, s []byte) []byte {
	h := sha3.New256()
	_, _ = h.Write(ntorV3Encap([]byte(t)))
	_, _ = h.Write(s)
	return h.Sum(nil)
}

func ntorV3MAC(t string, key, msg []byte) []byte {
	h := sha3.New256()
	_, _ = h.Write(ntorV3Encap([]byte(t)))
	_, _ = h.Write(ntorV3Encap(key))
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func ntorV3KDF(t string, s []byte, n int) []byte {
	xof := sha3.NewShake256()
	_, _ = xof.Write(ntorV3Encap([]byte(t)))
	_, _ = xof.Write(s)
	out := make([]byte, n)
	_, _ = xof.Read(out)
	return out
}

func ntorV3AESCTR(key, plaintext []byte) ([]byte, error) {
	if len(key) != NtorV3EncKeyLen {
		return nil, fmt.Errorf("ntor-v3 AES key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), plaintext...)
	iv := make([]byte, aes.BlockSize)
	cipher.NewCTR(block, iv).XORKeyStream(out, out)
	return out, nil
}

// EncodeNtorV3Extensions 编码 CM/SM：N_EXTENSIONS || (TYPE LEN DATA)*。
func EncodeNtorV3Extensions(exts []NtorV3Extension) []byte {
	if len(exts) > 255 {
		exts = exts[:255]
	}
	out := []byte{byte(len(exts))}
	for _, ext := range exts {
		if len(ext.Data) > 255 {
			continue
		}
		out = append(out, ext.Type, byte(len(ext.Data)))
		out = append(out, ext.Data...)
	}
	return out
}

// ParseNtorV3Extensions 解析并拒绝畸形编码。未知类型留给调用方忽略。
func ParseNtorV3Extensions(msg []byte) ([]NtorV3Extension, error) {
	if len(msg) < 1 {
		return nil, fmt.Errorf("ntor-v3 extra data missing N_EXTENSIONS")
	}
	n := int(msg[0])
	off := 1
	out := make([]NtorV3Extension, 0, n)
	seen := map[uint8]bool{}
	for i := 0; i < n; i++ {
		if off+2 > len(msg) {
			return nil, fmt.Errorf("ntor-v3 extra data truncated at extension %d", i)
		}
		typ := msg[off]
		ln := int(msg[off+1])
		off += 2
		if off+ln > len(msg) {
			return nil, fmt.Errorf("ntor-v3 extra data truncated body type=%d", typ)
		}
		data := append([]byte(nil), msg[off:off+ln]...)
		off += ln
		if seen[typ] {
			continue
		}
		seen[typ] = true
		out = append(out, NtorV3Extension{Type: typ, Data: data})
	}
	if off != len(msg) {
		return nil, fmt.Errorf("ntor-v3 extra data has %d trailing bytes", len(msg)-off)
	}
	return out, nil
}

// EncodeCCRequest 是最新 C Tor 客户端在 FlowCtrl=2 时发送的 CM。
func EncodeCCRequest() []byte {
	return EncodeNtorV3Extensions([]NtorV3Extension{{Type: NtorV3ExtCCRequest}})
}

// ParseCCSendmeInc 从服务端 SM 取出 sendme_inc。未协商则 ok=false。
func ParseCCSendmeInc(serverMsg []byte) (inc int, ok bool, err error) {
	exts, err := ParseNtorV3Extensions(serverMsg)
	if err != nil {
		return 0, false, err
	}
	for _, ext := range exts {
		if ext.Type == NtorV3ExtCCResponse {
			if len(ext.Data) != 1 {
				return 0, false, fmt.Errorf("CC_FIELD_RESPONSE length %d, want 1", len(ext.Data))
			}
			inc = int(ext.Data[0])
			if inc < 1 || inc > 250 {
				return 0, false, fmt.Errorf("sendme_inc %d out of range", inc)
			}
			return inc, true, nil
		}
	}
	return 0, false, nil
}

// NtorV3ClientHandshake 构造 CREATE2/EXTEND2 的 ntor-v3 onion skin。
//
// edID 必须是 32 字节 Ed25519 主身份。
// 普通电路扩展的 verification 必须是 NtorV3CircuitVerification。
// clientMsg 是加密前的 CM（含 N_EXTENSIONS）。
func NtorV3ClientHandshake(edID, onionKey, verification, clientMsg []byte) ([]byte, *NtorV3ClientState, error) {
	kp, err := GenerateNtorKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return ntorV3ClientHandshakeWithKey(edID, onionKey, verification, clientMsg, kp.Private[:])
}

func ntorV3ClientHandshakeWithKey(edID, onionKey, verification, clientMsg, priv []byte) ([]byte, *NtorV3ClientState, error) {
	if len(edID) != NtorV3IDLen {
		return nil, nil, fmt.Errorf("ntor-v3 ID length %d, want %d (Ed25519)", len(edID), NtorV3IDLen)
	}
	if len(onionKey) != NtorV3PubLen {
		return nil, nil, fmt.Errorf("ntor-v3 onion key length %d", len(onionKey))
	}
	if len(priv) != 32 {
		return nil, nil, fmt.Errorf("ntor-v3 ephemeral private length %d", len(priv))
	}
	if isAllZero(edID) || isAllZero(onionKey) {
		return nil, nil, fmt.Errorf("ntor-v3 identity or onion key is all zeros")
	}

	var x, X, B, Bx [32]byte
	copy(x[:], priv)
	copy(B[:], onionKey)
	curve25519.ScalarBaseMult(&X, &x)
	curve25519.ScalarMult(&Bx, &x, &B)
	if isAllZero(Bx[:]) {
		return nil, nil, fmt.Errorf("ntor-v3 EXP(B,x) produced the identity point")
	}

	phase1 := make([]byte, 0, 32+32+32+32+len(ntorV3ProtoID)+8+len(verification))
	phase1 = append(phase1, Bx[:]...)
	phase1 = append(phase1, edID...)
	phase1 = append(phase1, X[:]...)
	phase1 = append(phase1, B[:]...)
	phase1 = append(phase1, ntorV3ProtoID...)
	phase1 = append(phase1, ntorV3Encap(verification)...)
	keys := ntorV3KDF(ntorV3TMsgKDF, phase1, NtorV3EncKeyLen+NtorV3MACLen)
	encK1 := keys[:NtorV3EncKeyLen]
	macK1 := keys[NtorV3EncKeyLen:]

	encrypted, err := ntorV3AESCTR(encK1, clientMsg)
	if err != nil {
		return nil, nil, err
	}

	macMsg := make([]byte, 0, 32+32+32+len(encrypted))
	macMsg = append(macMsg, edID...)
	macMsg = append(macMsg, B[:]...)
	macMsg = append(macMsg, X[:]...)
	macMsg = append(macMsg, encrypted...)
	msgMAC := ntorV3MAC(ntorV3TMsgMAC, macK1, macMsg)

	skin := make([]byte, 0, NtorV3FixedClientLen+len(encrypted))
	skin = append(skin, edID...)
	skin = append(skin, B[:]...)
	skin = append(skin, X[:]...)
	skin = append(skin, encrypted...)
	skin = append(skin, msgMAC...)

	st := &NtorV3ClientState{
		x:      x,
		X:      X,
		B:      B,
		ID:     append([]byte(nil), edID...),
		Bx:     Bx,
		msgMAC: msgMAC,
	}
	return skin, st, nil
}

// NtorV3ProcessResponse 校验 AUTH 并导出 72 字节电路密钥与服务端 SM。
func NtorV3ProcessResponse(reply []byte, st *NtorV3ClientState, verification []byte) (keyMaterial, serverMsg []byte, err error) {
	if st == nil {
		return nil, nil, fmt.Errorf("missing ntor-v3 client state")
	}
	if len(reply) < NtorV3FixedServerLen {
		return nil, nil, fmt.Errorf("ntor-v3 reply too short: %d", len(reply))
	}
	var Y [32]byte
	copy(Y[:], reply[:32])
	auth := reply[32:64]
	encSM := reply[64:]
	if isAllZero(Y[:]) {
		return nil, nil, fmt.Errorf("ntor-v3 server ephemeral is the identity point")
	}

	var Yx [32]byte
	curve25519.ScalarMult(&Yx, &st.x, &Y)
	if isAllZero(Yx[:]) {
		return nil, nil, fmt.Errorf("ntor-v3 EXP(Y,x) produced the identity point")
	}

	secret := make([]byte, 0, 32+32+32+32+32+32+len(ntorV3ProtoID)+8+len(verification))
	secret = append(secret, Yx[:]...)
	secret = append(secret, st.Bx[:]...)
	secret = append(secret, st.ID...)
	secret = append(secret, st.B[:]...)
	secret = append(secret, st.X[:]...)
	secret = append(secret, Y[:]...)
	secret = append(secret, ntorV3ProtoID...)
	secret = append(secret, ntorV3Encap(verification)...)

	keySeed := ntorV3Hash(ntorV3TKeySeed, secret)
	verify := ntorV3Hash(ntorV3TVerify, secret)
	_ = keySeed

	authInput := make([]byte, 0, 32+32+32+32+32+32+8+len(encSM)+len(ntorV3ProtoID)+len(ntorV3ServerStr))
	authInput = append(authInput, verify...)
	authInput = append(authInput, st.ID...)
	authInput = append(authInput, st.B[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, st.X[:]...)
	authInput = append(authInput, st.msgMAC...)
	authInput = append(authInput, ntorV3Encap(encSM)...)
	authInput = append(authInput, ntorV3ProtoID...)
	authInput = append(authInput, ntorV3ServerStr...)
	expected := ntorV3Hash(ntorV3TAuth, authInput)
	if subtle.ConstantTimeCompare(auth, expected) != 1 {
		return nil, nil, fmt.Errorf("ntor-v3 AUTH verification failed")
	}

	raw := ntorV3KDF(ntorV3TFinal, keySeed, NtorV3EncKeyLen+NtorV3KeyMaterialLen)
	encKey := raw[:NtorV3EncKeyLen]
	keyMaterial = append([]byte(nil), raw[NtorV3EncKeyLen:]...)
	serverMsg, err = ntorV3AESCTR(encKey, encSM)
	if err != nil {
		return nil, nil, err
	}
	return keyMaterial, serverMsg, nil
}

// Wipe 清零客户端临时标量。
func (s *NtorV3ClientState) Wipe() {
	if s == nil {
		return
	}
	for i := range s.x {
		s.x[i] = 0
	}
}
