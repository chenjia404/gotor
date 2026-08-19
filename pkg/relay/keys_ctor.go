package relay

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
)

// C Tor tagged 密钥头（32 字节，含 NUL 填充）。
var (
	ctorEd25519SecretHeader = padTaggedHeader("== ed25519v1-secret: type0 ==")
	ctorNtorSecretHeader    = padTaggedHeader("== c25519v1-secret: type0 ==")
)

func padTaggedHeader(s string) []byte {
	h := make([]byte, 32)
	copy(h, s)
	return h
}

func encodeCTorEd25519Secret(priv ed25519.PrivateKey) []byte {
	out := make([]byte, 32+len(priv))
	copy(out, ctorEd25519SecretHeader)
	copy(out[32:], priv)
	return out
}

func parseEd25519Secret(data []byte) (ed25519.PrivateKey, error) {
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), data...)), nil
	}
	if len(data) == 32+ed25519.PrivateKeySize && headerPrefixMatch(data, ctorEd25519SecretHeader) {
		return ed25519.PrivateKey(append([]byte(nil), data[32:]...)), nil
	}
	if len(data) == 32+ed25519.SeedSize && headerPrefixMatch(data, ctorEd25519SecretHeader) {
		return ed25519.NewKeyFromSeed(data[32:]), nil
	}
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}
	return nil, fmt.Errorf("invalid Ed25519 key size: got %d, want %d", len(data), ed25519.PrivateKeySize)
}

func headerPrefixMatch(data, header []byte) bool {
	if len(data) < len(header) {
		return false
	}
	// 比较到第一个 NUL 为止，兼容填充差异
	n := 0
	for n < len(header) && header[n] != 0 {
		n++
	}
	if n == 0 || len(data) < n {
		return false
	}
	return string(data[:n]) == string(header[:n])
}

func encodeCTorNtorSecret(key []byte) []byte {
	out := make([]byte, 32+len(key))
	copy(out, ctorNtorSecretHeader)
	copy(out[32:], key)
	return out
}

func parseNtorSecret(data []byte) ([]byte, error) {
	if len(data) == 32 {
		return append([]byte(nil), data...), nil
	}
	if len(data) == 32+32 && headerPrefixMatch(data, ctorNtorSecretHeader) {
		return append([]byte(nil), data[32:]...), nil
	}
	return nil, fmt.Errorf("invalid ntor key size: %d", len(data))
}

func readFirstExisting(dir string, names ...string) ([]byte, error) {
	var last error
	for _, n := range names {
		p := filepath.Join(dir, n)
		b, err := os.ReadFile(p) // #nosec G304 -- DataDirectory/keys 由操作者配置
		if err == nil {
			return b, nil
		}
		last = err
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return nil, last
}
