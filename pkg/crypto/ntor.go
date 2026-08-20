// ntor 握手实现，对照 tor-spec create-created-cells “The ntor handshake”。
//
// 规范定义：
//
//	H(x,t) = HMAC-SHA256(key=t, msg=x)
//	ID_LENGTH = 20  （NODEID = SHA1(DER(KP_relayid_rsa))）
//	PROTOID   = "ntor-curve25519-sha256-1"
//	t_mac     = PROTOID | ":mac"
//	t_key     = PROTOID | ":key_extract"
//	t_verify  = PROTOID | ":verify"
//	m_expand  = PROTOID | ":key_expand"
//
//	secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
//	KEY_SEED     = H(secret_input, t_key)
//	verify       = H(secret_input, t_verify)
//	auth_input   = verify | ID | B | Y | X | PROTOID | "Server"
//	AUTH         = H(auth_input, t_mac)
//
// 电路密钥必须按 C Tor onion_ntor.c / Arti Ntor1Kdf：
//
//	HKDF-SHA256(IKM=secret_input, salt=t_key, info=m_expand)
//
// 这等于 HKDF-Expand(PRK=KEY_SEED, info=m_expand)。
// 禁止再对 KEY_SEED 做一次 Extract（IKM=KEY_SEED, salt=t_key）：
// AUTH 仍会通过，但 Df/Db/Kf/Kb 与 Guard 不一致，第一个 RELAY 会被 DESTROY reason=1。
//
// C Tor: src/core/crypto/onion_ntor.c
//
//	crypto_expand_key_material_rfc5869_sha256(secret_input, t_key, m_expand)
//
// Arti: crates/tor-proto/src/crypto/handshake/ntor.rs
//
//	Ntor1Kdf::derive(secret_input)
//
// Spec：https://spec.torproject.org/tor-spec/setting-circuit-keys.html （IKM == secret_input）
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ntorProtoID        = "ntor-curve25519-sha256-1"
	ntorTMac           = ntorProtoID + ":mac"
	ntorTKey           = ntorProtoID + ":key_extract"
	ntorTVerify        = ntorProtoID + ":verify"
	ntorMExpand        = ntorProtoID + ":key_expand"
	ntorServerStr      = "Server"
	NtorNodeIDLen      = 20
	NtorOnionKeyLen    = 32
	NtorHandshakeLen   = 84 // NODEID(20) || KEYID(32) || CLIENT_PK(32)
	NtorResponseLen    = 64 // Y(32) || AUTH(32)
	NtorKeyMaterialLen = 72 // Df(20) || Db(20) || Kf(16) || Kb(16)
	// NtorCircNonceLen：C Tor onion_skin_*_handshake 额外展开 DIGEST_LEN，供 ESTABLISH_INTRO MAC。
	NtorCircNonceLen = 20
	NtorExpandedLen  = NtorKeyMaterialLen + NtorCircNonceLen // 92
)

func ntorHMAC(key string, msg []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

func ntorExpandKeyMaterial(secretInput []byte) ([]byte, error) {
	// C Tor / Arti：IKM 是 secret_input，不是 KEY_SEED。
	// 展开 92 字节：前 72 为电路密钥，后 20 为 rend_circ_nonce（ESTABLISH_INTRO KH）。
	reader := hkdf.New(sha256.New, secretInput, []byte(ntorTKey), []byte(ntorMExpand))
	out := make([]byte, NtorExpandedLen)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("ntor HKDF-Expand failed: %w", err)
	}
	return out, nil
}

// SplitNtorExpanded 将 92 字节展开结果拆为电路密钥与 circ_nonce。
func SplitNtorExpanded(expanded []byte) (keyMaterial, circNonce []byte, err error) {
	if len(expanded) < NtorExpandedLen {
		return nil, nil, fmt.Errorf("ntor expanded material too short: %d", len(expanded))
	}
	km := make([]byte, NtorKeyMaterialLen)
	copy(km, expanded[:NtorKeyMaterialLen])
	cn := make([]byte, NtorCircNonceLen)
	copy(cn, expanded[NtorKeyMaterialLen:NtorExpandedLen])
	return km, cn, nil
}

func isAllZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

func ntorBuildSecretInput(sharedXY, sharedXB, nodeID, serverB, clientX, serverY []byte) []byte {
	secret := make([]byte, 0, 32+32+NtorNodeIDLen+32+32+32+len(ntorProtoID))
	secret = append(secret, sharedXY...)
	secret = append(secret, sharedXB...)
	secret = append(secret, nodeID...)
	secret = append(secret, serverB...)
	secret = append(secret, clientX...)
	secret = append(secret, serverY...)
	secret = append(secret, ntorProtoID...)
	return secret
}

func ntorComputeAuth(verify, nodeID, serverB, serverY, clientX []byte) []byte {
	authInput := make([]byte, 0, 32+NtorNodeIDLen+32+32+32+len(ntorProtoID)+len(ntorServerStr))
	authInput = append(authInput, verify...)
	authInput = append(authInput, nodeID...)
	authInput = append(authInput, serverB...)
	authInput = append(authInput, serverY...)
	authInput = append(authInput, clientX...)
	authInput = append(authInput, ntorProtoID...)
	authInput = append(authInput, ntorServerStr...)
	return ntorHMAC(ntorTMac, authInput)
}

func ntorDerive(secretInput []byte) (keySeed, verify []byte) {
	keySeed = ntorHMAC(ntorTKey, secretInput)
	verify = ntorHMAC(ntorTVerify, secretInput)
	return keySeed, verify
}

// NtorClientHandshake 构造 CREATE2/EXTEND2 的客户端 ntor 握手数据。
//
// nodeID 必须是 20 字节 RSA identity digest（共识 r 行 identity / SHA1(DER(RSA))）。
// 禁止传入 Ed25519 公钥或对其做截断。
//
// 第二个返回值是临时私钥 x，必须交给 NtorProcessResponse，用完后清零。
func NtorClientHandshake(nodeID, ntorOnionKey []byte) (handshakeData, ephemeralPrivate []byte, err error) {
	if len(nodeID) != NtorNodeIDLen {
		return nil, nil, fmt.Errorf("invalid ntor NODEID length: %d, expected %d (RSA SHA-1 fingerprint)", len(nodeID), NtorNodeIDLen)
	}
	if len(ntorOnionKey) != NtorOnionKeyLen {
		return nil, nil, fmt.Errorf("invalid ntor onion key length: %d, expected %d", len(ntorOnionKey), NtorOnionKeyLen)
	}
	if isAllZero(nodeID) {
		return nil, nil, fmt.Errorf("ntor NODEID is all zeros")
	}
	if isAllZero(ntorOnionKey) {
		return nil, nil, fmt.Errorf("ntor onion key is all zeros")
	}

	ephemeral, err := GenerateNtorKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	handshakeData = make([]byte, NtorHandshakeLen)
	copy(handshakeData[0:20], nodeID)
	copy(handshakeData[20:52], ntorOnionKey)
	copy(handshakeData[52:84], ephemeral.Public[:])

	ephemeralPrivate = make([]byte, 32)
	copy(ephemeralPrivate, ephemeral.Private[:])
	return handshakeData, ephemeralPrivate, nil
}

// NtorProcessResponse 验证 CREATED2/EXTENDED2 中的 AUTH，并导出 72 字节电路密钥。
//
// serverNodeID 必须是 20 字节 RSA fingerprint，与握手 NODEID 相同。
func NtorProcessResponse(response, clientPrivate, serverNtorKey, serverNodeID []byte) ([]byte, error) {
	km, _, err := NtorProcessResponseWithNonce(response, clientPrivate, serverNtorKey, serverNodeID)
	return km, err
}

// NtorProcessResponseWithNonce 返回电路密钥与 rend_circ_nonce（ESTABLISH_INTRO MAC 密钥）。
func NtorProcessResponseWithNonce(response, clientPrivate, serverNtorKey, serverNodeID []byte) (keyMaterial, circNonce []byte, err error) {
	if len(response) != NtorResponseLen {
		return nil, nil, fmt.Errorf("invalid ntor response length: %d, expected %d", len(response), NtorResponseLen)
	}
	if len(clientPrivate) != 32 {
		return nil, nil, fmt.Errorf("invalid client ephemeral private key length: %d", len(clientPrivate))
	}
	if len(serverNtorKey) != NtorOnionKeyLen {
		return nil, nil, fmt.Errorf("invalid ntor onion key length: %d", len(serverNtorKey))
	}
	if len(serverNodeID) != NtorNodeIDLen {
		return nil, nil, fmt.Errorf("invalid ntor NODEID length: %d, expected %d", len(serverNodeID), NtorNodeIDLen)
	}

	var serverY, auth, clientX, serverB [32]byte
	copy(serverY[:], response[0:32])
	copy(auth[:], response[32:64])
	copy(clientX[:], clientPrivate)
	copy(serverB[:], serverNtorKey)

	if isAllZero(serverY[:]) {
		return nil, nil, fmt.Errorf("ntor server ephemeral public key is the identity point")
	}

	var sharedXY, sharedXB [32]byte
	curve25519.ScalarMult(&sharedXY, &clientX, &serverY)
	curve25519.ScalarMult(&sharedXB, &clientX, &serverB)
	if isAllZero(sharedXY[:]) || isAllZero(sharedXB[:]) {
		return nil, nil, fmt.Errorf("ntor EXP() produced the identity point")
	}

	var clientPub [32]byte
	curve25519.ScalarBaseMult(&clientPub, &clientX)

	secretInput := ntorBuildSecretInput(sharedXY[:], sharedXB[:], serverNodeID, serverNtorKey, clientPub[:], serverY[:])
	_, verify := ntorDerive(secretInput)
	expectedAuth := ntorComputeAuth(verify, serverNodeID, serverNtorKey, serverY[:], clientPub[:])

	if subtle.ConstantTimeCompare(auth[:], expectedAuth) != 1 {
		return nil, nil, fmt.Errorf("ntor AUTH verification failed: server authentication invalid")
	}

	expanded, err := ntorExpandKeyMaterial(secretInput)
	if err != nil {
		return nil, nil, err
	}
	return SplitNtorExpanded(expanded)
}

func ntorServerHandshakeCore(clientHandshake, serverNtorPrivate, serverNodeID, ephemeralPrivate []byte) (response, keyMaterial []byte, err error) {
	if len(clientHandshake) != NtorHandshakeLen {
		return nil, nil, fmt.Errorf("invalid client handshake length: %d, expected %d", len(clientHandshake), NtorHandshakeLen)
	}
	if len(serverNtorPrivate) != 32 {
		return nil, nil, fmt.Errorf("invalid server ntor key length: %d", len(serverNtorPrivate))
	}
	if len(serverNodeID) != NtorNodeIDLen {
		return nil, nil, fmt.Errorf("invalid ntor NODEID length: %d, expected %d", len(serverNodeID), NtorNodeIDLen)
	}

	clientNodeID := clientHandshake[0:20]
	clientKeyID := clientHandshake[20:52]
	var clientPK [32]byte
	copy(clientPK[:], clientHandshake[52:84])

	if subtle.ConstantTimeCompare(clientNodeID, serverNodeID) != 1 {
		return nil, nil, fmt.Errorf("ntor NODEID mismatch")
	}

	var serverB [32]byte
	copy(serverB[:], serverNtorPrivate)
	var serverPublic [32]byte
	curve25519.ScalarBaseMult(&serverPublic, &serverB)
	if subtle.ConstantTimeCompare(clientKeyID, serverPublic[:]) != 1 {
		return nil, nil, fmt.Errorf("ntor KEYID mismatch")
	}

	var serverEphemeral *NtorKeyPair
	if ephemeralPrivate != nil {
		if len(ephemeralPrivate) != 32 {
			return nil, nil, fmt.Errorf("ephemeralPrivate must be exactly 32 bytes, got %d", len(ephemeralPrivate))
		}
		serverEphemeral = &NtorKeyPair{}
		copy(serverEphemeral.Private[:], ephemeralPrivate)
		curve25519.ScalarBaseMult(&serverEphemeral.Public, &serverEphemeral.Private)
	} else {
		serverEphemeral, err = GenerateNtorKeyPair()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate server ephemeral key: %w", err)
		}
	}

	var sharedXY, sharedXB [32]byte
	curve25519.ScalarMult(&sharedXY, &serverEphemeral.Private, &clientPK)
	curve25519.ScalarMult(&sharedXB, &serverB, &clientPK)
	if isAllZero(sharedXY[:]) || isAllZero(sharedXB[:]) {
		return nil, nil, fmt.Errorf("ntor EXP() produced the identity point")
	}

	secretInput := ntorBuildSecretInput(sharedXY[:], sharedXB[:], serverNodeID, serverPublic[:], clientPK[:], serverEphemeral.Public[:])
	_, verify := ntorDerive(secretInput)
	auth := ntorComputeAuth(verify, serverNodeID, serverPublic[:], serverEphemeral.Public[:], clientPK[:])

	keyMaterial, err = ntorExpandKeyMaterial(secretInput)
	if err != nil {
		return nil, nil, err
	}

	response = make([]byte, NtorResponseLen)
	copy(response[0:32], serverEphemeral.Public[:])
	copy(response[32:64], auth)
	return response, keyMaterial, nil
}
