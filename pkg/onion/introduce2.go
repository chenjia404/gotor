// Package onion - INTRODUCE2 Cell Parsing（hs-ntor）
// Following rend-spec-v3 NTOR-WITH-EXTRA-DATA
package onion

import (
	"encoding/binary"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/crypto"
)

// Introduce2Request contains parsed data needed to establish rendezvous.
type Introduce2Request struct {
	RendezvousCookie []byte           // 20-byte cookie for rendezvous point
	LinkSpecifiers   []LinkSpecifier  // Rendezvous point address info
	ClientOnionKey   []byte           // Client's ephemeral X (32 bytes) for hs-ntor
	IntroAuthKey     []byte           // AUTH_KEY from cell (Ed25519, 32 bytes)
	Extensions       map[uint8][]byte // Extension data (type -> value)
}

// ParseIntroduce2 解析并解密 INTRODUCE2（hs-ntor）。
//
// 格式（rend-spec）：
//
//	LEGACY_KEY_ID [20]（现为全零）
//	AUTH_KEY_TYPE [1] = 0x02
//	AUTH_KEY_LEN  [2]
//	AUTH_KEY      [32]
//	N_EXTENSIONS  [1]
//	EXTENSIONS...
//	ENCRYPTED = X[32] || C || MAC[32]
//
// introEncPriv 为引言点 Curve25519 私钥 b；subcred 为 N_hs_subcred。
func ParseIntroduce2(cell, introEncPriv, subcred []byte) (*Introduce2Request, error) {
	if len(cell) < 20+1+2+32+1+32+32 {
		return nil, fmt.Errorf("INTRODUCE2 cell too short: %d bytes", len(cell))
	}
	if len(introEncPriv) != 32 {
		return nil, fmt.Errorf("intro enc private key must be 32 bytes")
	}
	if len(subcred) != 32 {
		return nil, fmt.Errorf("subcredential must be 32 bytes")
	}

	offset := 0
	// LEGACY_KEY_ID（20 字节，现规范填零；兼容直接从 AUTH_KEY_TYPE 开始的旧测试向量）
	if cell[0] == 0x00 && len(cell) > 23 && cell[20] == 0x02 {
		offset = 20
	}

	authKeyType := cell[offset]
	offset++
	if authKeyType != 0x02 {
		return nil, fmt.Errorf("unsupported auth key type: 0x%02x", authKeyType)
	}
	authKeyLen := binary.BigEndian.Uint16(cell[offset : offset+2])
	offset += 2
	if authKeyLen != 32 {
		return nil, fmt.Errorf("invalid auth key length: %d", authKeyLen)
	}
	if offset+32 > len(cell) {
		return nil, fmt.Errorf("truncated AUTH_KEY")
	}
	authKey := make([]byte, 32)
	copy(authKey, cell[offset:offset+32])
	offset += 32

	if offset >= len(cell) {
		return nil, fmt.Errorf("truncated N_EXTENSIONS")
	}
	nExt := int(cell[offset])
	offset++
	for i := 0; i < nExt; i++ {
		// INTRODUCE 扩展：TYPE[1] LEN[1] DATA[LEN]（rend-spec）
		if offset+2 > len(cell) {
			return nil, fmt.Errorf("truncated extension header")
		}
		offset++ // type
		extLen := int(cell[offset])
		offset++
		if offset+extLen > len(cell) {
			return nil, fmt.Errorf("truncated extension data")
		}
		offset += extLen
	}

	header := cell[:offset] // H：MAC 覆盖 H|X|C
	rest := cell[offset:]
	if len(rest) < 32+32 {
		return nil, fmt.Errorf("encrypted section too short: %d", len(rest))
	}
	X := rest[:32]
	mac := rest[len(rest)-32:]
	ciphertext := rest[32 : len(rest)-32]

	encKey, macKey, _, err := crypto.HsNtorServiceIntroKeys(introEncPriv, X, authKey, subcred)
	if err != nil {
		return nil, fmt.Errorf("hs-ntor intro keys: %w", err)
	}

	macBody := make([]byte, 0, len(header)+32+len(ciphertext))
	macBody = append(macBody, header...)
	macBody = append(macBody, X...)
	macBody = append(macBody, ciphertext...)
	expectedMAC := crypto.HsMAC(macKey, macBody)
	if !crypto.ConstantTimeCompare(mac, expectedMAC) {
		return nil, fmt.Errorf("INTRODUCE2 MAC verification failed")
	}

	plaintext, err := crypto.DecryptAES256CTR(ciphertext, encKey, make([]byte, 16))
	if err != nil {
		return nil, fmt.Errorf("INTRODUCE2 decrypt: %w", err)
	}

	req, err := parseIntroduce2Inner(plaintext)
	if err != nil {
		return nil, err
	}
	req.IntroAuthKey = authKey
	// ClientOnionKey 在内层也可能有 ONION_KEY；hs-ntor 的 X 才是握手公钥。
	// 保留内层 ONION_KEY 若存在，但以 X 作为 ClientOnionKey（与 RENDEZVOUS1 一致）。
	req.ClientOnionKey = append([]byte(nil), X...)
	return req, nil
}

func parseIntroduce2Inner(plaintext []byte) (*Introduce2Request, error) {
	if len(plaintext) < 20+1 {
		return nil, fmt.Errorf("decrypted data too short: %d bytes", len(plaintext))
	}
	offset := 0
	rendezvousCookie := make([]byte, 20)
	copy(rendezvousCookie, plaintext[offset:offset+20])
	offset += 20

	nspec := plaintext[offset]
	offset++
	linkSpecifiers := make([]LinkSpecifier, 0, nspec)
	for i := 0; i < int(nspec); i++ {
		if offset+2 > len(plaintext) {
			return nil, fmt.Errorf("truncated link specifier %d", i)
		}
		lstype := plaintext[offset]
		offset++
		lslen := plaintext[offset]
		offset++
		if offset+int(lslen) > len(plaintext) {
			return nil, fmt.Errorf("truncated link specifier %d data", i)
		}
		lsdata := make([]byte, lslen)
		copy(lsdata, plaintext[offset:offset+int(lslen)])
		offset += int(lslen)
		linkSpecifiers = append(linkSpecifiers, LinkSpecifier{Type: lstype, Data: lsdata})
	}

	extensions := make(map[uint8][]byte)
	// 可选 ONION_KEY（旧格式）；新格式握手密钥已在外层 X
	if offset+3 <= len(plaintext) {
		onionKeyType := plaintext[offset]
		if onionKeyType == 0x00 {
			offset++
			onionKeyLen := binary.BigEndian.Uint16(plaintext[offset : offset+2])
			offset += 2
			if offset+int(onionKeyLen) <= len(plaintext) {
				offset += int(onionKeyLen)
			}
		}
	}
	if offset < len(plaintext) {
		nExt := int(plaintext[offset])
		offset++
		for i := 0; i < nExt; i++ {
			if offset+3 > len(plaintext) {
				break
			}
			extType := plaintext[offset]
			offset++
			extLen := binary.BigEndian.Uint16(plaintext[offset : offset+2])
			offset += 2
			if offset+int(extLen) > len(plaintext) {
				break
			}
			extData := make([]byte, extLen)
			copy(extData, plaintext[offset:offset+int(extLen)])
			offset += int(extLen)
			extensions[extType] = extData
		}
	}

	return &Introduce2Request{
		RendezvousCookie: rendezvousCookie,
		LinkSpecifiers:   linkSpecifiers,
		Extensions:       extensions,
	}, nil
}

// BuildIntroduce1Encrypted 客户端构造 INTRODUCE1 的 ENCRYPTED 段：X || C || M。
// header 为 LEGACY_KEY_ID…EXTENSIONS（不含 ENCRYPTED）。
func BuildIntroduce1Encrypted(header, plaintext, xPriv, B, authKey, subcred []byte) ([]byte, error) {
	encKey, macKey, X, err := crypto.HsNtorClientIntroKeys(xPriv, B, authKey, subcred)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.EncryptAES256CTR(plaintext, encKey, make([]byte, 16))
	if err != nil {
		return nil, err
	}
	macBody := make([]byte, 0, len(header)+32+len(ciphertext))
	macBody = append(macBody, header...)
	macBody = append(macBody, X...)
	macBody = append(macBody, ciphertext...)
	mac := crypto.HsMAC(macKey, macBody)
	out := make([]byte, 0, 32+len(ciphertext)+32)
	out = append(out, X...)
	out = append(out, ciphertext...)
	out = append(out, mac...)
	return out, nil
}

// LinkSpecifierToAddress converts link specifiers to an address string
func LinkSpecifierToAddress(specs []LinkSpecifier) (string, error) {
	for _, spec := range specs {
		switch spec.Type {
		case 0x00: // TLS-over-TCP-IPv4
			if len(spec.Data) == 6 {
				ip := fmt.Sprintf("%d.%d.%d.%d", spec.Data[0], spec.Data[1], spec.Data[2], spec.Data[3])
				port := binary.BigEndian.Uint16(spec.Data[4:6])
				return fmt.Sprintf("%s:%d", ip, port), nil
			}
		case 0x01: // TLS-over-TCP-IPv6
			if len(spec.Data) == 18 {
				port := binary.BigEndian.Uint16(spec.Data[16:18])
				return fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d",
					spec.Data[0], spec.Data[1], spec.Data[2], spec.Data[3],
					spec.Data[4], spec.Data[5], spec.Data[6], spec.Data[7],
					spec.Data[8], spec.Data[9], spec.Data[10], spec.Data[11],
					spec.Data[12], spec.Data[13], spec.Data[14], spec.Data[15],
					port), nil
			}
		}
	}
	return "", fmt.Errorf("no supported link specifier found")
}
