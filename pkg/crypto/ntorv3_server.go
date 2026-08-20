// Package crypto — ntor-v3 服务端握手（CREATE2 HTYPE=0x0003）。
package crypto

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// NtorV3ServerHandshake 处理客户端 onion skin，返回 CREATED2 握手数据与电路密钥。
//
// edID / onionPriv 为本中继 Ed25519 身份与 Curve25519 ntor 私钥；
// verification 对普通电路为 NtorV3CircuitVerification。
// serverMsgPlain 为加密前的 SM（通常含 CC_FIELD_RESPONSE）；可为空扩展 EncodeNtorV3Extensions(nil)。
func NtorV3ServerHandshake(clientSkin, edID, onionPriv, verification, serverMsgPlain []byte) (response, keyMaterial []byte, err error) {
	resp, km, _, err := ntorV3ServerHandshakeCore(clientSkin, edID, onionPriv, verification, serverMsgPlain)
	return resp, km, err
}

// NtorV3ServerHandshakeWithNonce 与 NtorV3ServerHandshake 相同，并返回 rend_circ_nonce。
func NtorV3ServerHandshakeWithNonce(clientSkin, edID, onionPriv, verification, serverMsgPlain []byte) (response, keyMaterial, circNonce []byte, err error) {
	return ntorV3ServerHandshakeCore(clientSkin, edID, onionPriv, verification, serverMsgPlain)
}

func ntorV3ServerHandshakeCore(clientSkin, edID, onionPriv, verification, serverMsgPlain []byte) (response, keyMaterial, circNonce []byte, err error) {
	if len(edID) != NtorV3IDLen {
		return nil, nil, nil, fmt.Errorf("ntor-v3 server ID length %d", len(edID))
	}
	if len(onionPriv) != 32 {
		return nil, nil, nil, fmt.Errorf("ntor-v3 onion private length %d", len(onionPriv))
	}
	if len(clientSkin) < NtorV3FixedClientLen {
		return nil, nil, nil, fmt.Errorf("ntor-v3 client skin too short: %d", len(clientSkin))
	}

	id := clientSkin[:32]
	Bclaimed := clientSkin[32:64]
	var X [32]byte
	copy(X[:], clientSkin[64:96])
	encCM := clientSkin[96 : len(clientSkin)-NtorV3MACLen]
	msgMAC := clientSkin[len(clientSkin)-NtorV3MACLen:]

	if subtle.ConstantTimeCompare(id, edID) != 1 {
		return nil, nil, nil, fmt.Errorf("ntor-v3 identity mismatch")
	}

	var b, B [32]byte
	copy(b[:], onionPriv)
	curve25519.ScalarBaseMult(&B, &b)
	if subtle.ConstantTimeCompare(Bclaimed, B[:]) != 1 {
		return nil, nil, nil, fmt.Errorf("ntor-v3 onion KEYID mismatch")
	}
	if isAllZero(X[:]) {
		return nil, nil, nil, fmt.Errorf("ntor-v3 client ephemeral is identity")
	}

	var Bx [32]byte
	curve25519.ScalarMult(&Bx, &b, &X)
	if isAllZero(Bx[:]) {
		return nil, nil, nil, fmt.Errorf("ntor-v3 EXP(X,b) identity")
	}

	phase1 := make([]byte, 0, 32+32+32+32+len(ntorV3ProtoID)+8+len(verification))
	phase1 = append(phase1, Bx[:]...)
	phase1 = append(phase1, edID...)
	phase1 = append(phase1, X[:]...)
	phase1 = append(phase1, B[:]...)
	phase1 = append(phase1, ntorV3ProtoID...)
	phase1 = append(phase1, ntorV3Encap(verification)...)
	keys1 := ntorV3KDF(ntorV3TMsgKDF, phase1, NtorV3EncKeyLen+NtorV3MACLen)
	encK1 := keys1[:NtorV3EncKeyLen]
	macK1 := keys1[NtorV3EncKeyLen:]

	macMsg := make([]byte, 0, 32+32+32+len(encCM))
	macMsg = append(macMsg, edID...)
	macMsg = append(macMsg, B[:]...)
	macMsg = append(macMsg, X[:]...)
	macMsg = append(macMsg, encCM...)
	expectedMAC := ntorV3MAC(ntorV3TMsgMAC, macK1, macMsg)
	if subtle.ConstantTimeCompare(msgMAC, expectedMAC) != 1 {
		return nil, nil, nil, fmt.Errorf("ntor-v3 client MSG MAC mismatch")
	}

	// 解密 CM（本实现暂不强制解析扩展）
	if _, err := ntorV3AESCTR(encK1, encCM); err != nil {
		return nil, nil, nil, fmt.Errorf("ntor-v3 decrypt CM: %w", err)
	}

	yKP, err := GenerateNtorKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	var y, Y [32]byte
	copy(y[:], yKP.Private[:])
	copy(Y[:], yKP.Public[:])

	var Yx [32]byte
	curve25519.ScalarMult(&Yx, &y, &X)
	if isAllZero(Yx[:]) {
		return nil, nil, nil, fmt.Errorf("ntor-v3 EXP(X,y) identity")
	}

	secret := make([]byte, 0, 32+32+32+32+32+32+len(ntorV3ProtoID)+8+len(verification))
	secret = append(secret, Yx[:]...)
	secret = append(secret, Bx[:]...)
	secret = append(secret, edID...)
	secret = append(secret, B[:]...)
	secret = append(secret, X[:]...)
	secret = append(secret, Y[:]...)
	secret = append(secret, ntorV3ProtoID...)
	secret = append(secret, ntorV3Encap(verification)...)

	keySeed := ntorV3Hash(ntorV3TKeySeed, secret)
	verify := ntorV3Hash(ntorV3TVerify, secret)

	if serverMsgPlain == nil {
		serverMsgPlain = EncodeNtorV3Extensions(nil)
	}
	rawFinal := ntorV3KDF(ntorV3TFinal, keySeed, NtorV3EncKeyLen+NtorV3KeyMaterialLen+NtorCircNonceLen)
	encKey := rawFinal[:NtorV3EncKeyLen]
	keyMaterial = append([]byte(nil), rawFinal[NtorV3EncKeyLen:NtorV3EncKeyLen+NtorV3KeyMaterialLen]...)
	circNonce = append([]byte(nil), rawFinal[NtorV3EncKeyLen+NtorV3KeyMaterialLen:]...)

	encSM, err := ntorV3AESCTR(encKey, serverMsgPlain)
	if err != nil {
		return nil, nil, nil, err
	}

	authInput := make([]byte, 0, 32+32+32+32+32+32+8+len(encSM)+len(ntorV3ProtoID)+len(ntorV3ServerStr))
	authInput = append(authInput, verify...)
	authInput = append(authInput, edID...)
	authInput = append(authInput, B[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, X[:]...)
	authInput = append(authInput, msgMAC...)
	authInput = append(authInput, ntorV3Encap(encSM)...)
	authInput = append(authInput, ntorV3ProtoID...)
	authInput = append(authInput, ntorV3ServerStr...)
	auth := ntorV3Hash(ntorV3TAuth, authInput)

	response = make([]byte, 0, 32+32+len(encSM))
	response = append(response, Y[:]...)
	response = append(response, auth...)
	response = append(response, encSM...)
	return response, keyMaterial, circNonce, nil
}
