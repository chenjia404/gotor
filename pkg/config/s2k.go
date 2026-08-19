// Package config — C Tor 兼容的 HashedControlPassword（RFC2440 迭代加盐 S2K）。
//
// 格式见 control-spec implementation-notes：
//
//	16:HEX(salt[8] || indicator[1] || sha1[20])
//
// indicator 常用 0x60 → count = (16+(c&15)) << ((c>>4)+6) = 65536。
package config

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // C Tor 规定 SHA-1 S2K，非自选
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	s2kPrefix       = "16:"
	s2kSaltLen      = 8
	s2kIndicator    = byte(0x60) // C Tor --hash-password 默认
	s2kDigestLen    = 20
	s2kSpecTotalLen = s2kSaltLen + 1 + s2kDigestLen // 29 bytes
)

// s2kCountFromIndicator 按 RFC2440 / C Tor 解码迭代字节数。
func s2kCountFromIndicator(c byte) int {
	return (16 + int(c&15)) << (uint(c>>4) + 6)
}

// HashControlPassword 生成与 `tor --hash-password` 同格式的串。
func HashControlPassword(password string) (string, error) {
	salt := make([]byte, s2kSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return encodeHashedControlPassword(password, salt, s2kIndicator), nil
}

// HashControlPasswordWithSalt 供测试固定盐。
func HashControlPasswordWithSalt(password string, salt []byte, indicator byte) (string, error) {
	if len(salt) != s2kSaltLen {
		return "", fmt.Errorf("salt must be %d bytes", s2kSaltLen)
	}
	return encodeHashedControlPassword(password, salt, indicator), nil
}

func encodeHashedControlPassword(password string, salt []byte, indicator byte) string {
	digest := secretToKeyRFC2440(password, salt, indicator)
	out := make([]byte, 0, s2kSpecTotalLen)
	out = append(out, salt...)
	out = append(out, indicator)
	out = append(out, digest...)
	return s2kPrefix + strings.ToUpper(hex.EncodeToString(out))
}

// VerifyHashedControlPassword 校验明文是否匹配 HashedControlPassword。
func VerifyHashedControlPassword(password, hashed string) bool {
	hashed = strings.TrimSpace(hashed)
	if !strings.HasPrefix(hashed, s2kPrefix) {
		return false
	}
	raw, err := hex.DecodeString(hashed[len(s2kPrefix):])
	if err != nil || len(raw) != s2kSpecTotalLen {
		return false
	}
	salt := raw[:s2kSaltLen]
	indicator := raw[s2kSaltLen]
	stored := raw[s2kSaltLen+1:]
	computed := secretToKeyRFC2440(password, salt, indicator)
	return subtle.ConstantTimeCompare(computed, stored) == 1
}

func secretToKeyRFC2440(password string, salt []byte, indicator byte) []byte {
	count := s2kCountFromIndicator(indicator)
	input := append(append([]byte{}, salt...), []byte(password)...)
	if len(input) == 0 {
		return make([]byte, s2kDigestLen)
	}
	// #nosec G401 -- C Tor HashedControlPassword 强制 RFC2440 迭代加盐 SHA-1 S2K，非自选口令哈希
	h := sha1.New() //nolint:gosec
	written := 0
	for written < count {
		n := len(input)
		if written+n > count {
			n = count - written
		}
		_, _ = h.Write(input[:n])
		written += n
	}
	sum := h.Sum(nil)
	out := make([]byte, s2kDigestLen)
	copy(out, sum)
	return out
}
