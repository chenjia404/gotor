// Package onion — HS 描述符双层解密（rend-spec-v3 §2.5）。
package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/opd-ai/go-tor/pkg/crypto"
	"golang.org/x/crypto/sha3"
)

const (
	hsDescSaltLen   = 16
	hsDescMACLen    = 32
	hsDescKeyLen    = 32
	hsDescIVLen     = 16
	hsDescMACKeyLen = 32
)

// DecryptDescriptor 解密 superencrypted → encrypted → 引言点明文。
func DecryptDescriptor(descriptor *Descriptor, address *Address, timePeriod uint64) (*Descriptor, error) {
	if descriptor == nil {
		return nil, fmt.Errorf("descriptor is nil")
	}
	if address == nil {
		return nil, fmt.Errorf("address is nil")
	}
	if len(address.Pubkey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(address.Pubkey))
	}

	blinded := descriptor.BlindedPubkey
	if len(blinded) != 32 {
		blinded = ComputeBlindedPubkey(ed25519.PublicKey(address.Pubkey), timePeriod)
	}
	subcred := ComputeHSSubcredential(address.Pubkey, blinded)
	rev := descriptor.RevisionCounter

	raw := descriptor.RawDescriptor
	superBlob, err := extractArmoredBlob(raw, "superencrypted")
	if err != nil {
		// 无加密段则视为已解密
		if bytes.Contains(raw, []byte("introduction-point")) {
			return descriptor, nil
		}
		return nil, err
	}

	outerPlain, err := decryptHSDescLayer(superBlob, blinded, subcred, rev, "hsdir-superencrypted-data")
	if err != nil {
		return nil, fmt.Errorf("superencrypted layer: %w", err)
	}

	innerBlob, err := extractArmoredBlob(outerPlain, "encrypted")
	if err != nil {
		return nil, fmt.Errorf("inner encrypted field: %w", err)
	}

	// 无客户端授权时 SECRET_DATA = blinded-public-key
	innerPlain, err := decryptHSDescLayer(innerBlob, blinded, subcred, rev, "hsdir-encrypted-data")
	if err != nil {
		return nil, fmt.Errorf("encrypted layer: %w", err)
	}

	out := *descriptor
	out.IntroPoints = nil
	parsed, err := parseDecryptedLayer(innerPlain)
	if err == nil && parsed != nil && len(parsed.IntroPoints) > 0 {
		out.IntroPoints = parsed.IntroPoints
	} else {
		out.IntroPoints = parseIntroPointsFromPlaintext(innerPlain)
	}
	return &out, nil
}

func decryptHSDescLayer(blob, secretData, subcred []byte, revision uint64, stringConstant string) ([]byte, error) {
	if len(blob) < hsDescSaltLen+hsDescMACLen {
		return nil, fmt.Errorf("ciphertext too short: %d", len(blob))
	}
	salt := blob[:hsDescSaltLen]
	mac := blob[len(blob)-hsDescMACLen:]
	encrypted := blob[hsDescSaltLen : len(blob)-hsDescMACLen]

	secretInput := make([]byte, 0, len(secretData)+32+8)
	secretInput = append(secretInput, secretData...)
	secretInput = append(secretInput, subcred...)
	var revBuf [8]byte
	binary.BigEndian.PutUint64(revBuf[:], revision)
	secretInput = append(secretInput, revBuf[:]...)

	kdfIn := make([]byte, 0, len(secretInput)+len(salt)+len(stringConstant))
	kdfIn = append(kdfIn, secretInput...)
	kdfIn = append(kdfIn, salt...)
	kdfIn = append(kdfIn, stringConstant...)

	keys := make([]byte, hsDescKeyLen+hsDescIVLen+hsDescMACKeyLen)
	sha3.ShakeSum256(keys, kdfIn)
	secretKey := keys[:hsDescKeyLen]
	secretIV := keys[hsDescKeyLen : hsDescKeyLen+hsDescIVLen]
	macKey := keys[hsDescKeyLen+hsDescIVLen:]

	expected := hsDescMAC(macKey, salt, encrypted)
	if !crypto.ConstantTimeCompare(mac, expected) {
		return nil, fmt.Errorf("layer MAC mismatch")
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, secretIV)
	plain := make([]byte, len(encrypted))
	stream.XORKeyStream(plain, encrypted)
	// 去掉 NUL padding
	plain = bytes.TrimRight(plain, "\x00")
	return plain, nil
}

func hsDescMAC(macKey, salt, encrypted []byte) []byte {
	h := sha3.New256()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(macKey)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(macKey)
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(salt)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(salt)
	_, _ = h.Write(encrypted)
	return h.Sum(nil)
}

func extractArmoredBlob(doc []byte, keyword string) ([]byte, error) {
	idx := bytes.Index(doc, []byte(keyword))
	if idx < 0 {
		return nil, fmt.Errorf("%s not found", keyword)
	}
	rest := doc[idx:]
	begin := []byte("-----BEGIN MESSAGE-----")
	end := []byte("-----END MESSAGE-----")
	b := bytes.Index(rest, begin)
	if b < 0 {
		return nil, fmt.Errorf("%s missing BEGIN MESSAGE", keyword)
	}
	b += len(begin)
	e := bytes.Index(rest[b:], end)
	if e < 0 {
		return nil, fmt.Errorf("%s missing END MESSAGE", keyword)
	}
	b64 := strings.TrimSpace(string(rest[b : b+e]))
	b64 = strings.ReplaceAll(b64, "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")
	data, err := decodeDescriptorBase64(b64)
	if err != nil {
		// 兼容 StdEncoding 带换行已剥除
		data, err = base64.StdEncoding.DecodeString(b64)
	}
	if err != nil {
		return nil, fmt.Errorf("decode %s blob: %w", keyword, err)
	}
	return data, nil
}

func parseIntroPointsFromPlaintext(plain []byte) []IntroductionPoint {
	// 复用 ParseDescriptor：加假头以便 switch 解析
	wrapped := append([]byte("hs-descriptor 3\nrevision-counter 0\n"), plain...)
	d, err := ParseDescriptor(wrapped)
	if err != nil || d == nil {
		return nil
	}
	return d.IntroPoints
}
