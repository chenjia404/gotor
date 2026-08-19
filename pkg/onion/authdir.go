package onion

import (
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadClientAuthDir 读取 C Tor ClientOnionAuthDir 下的 *.auth_private。
// 格式：<onion>:descriptor:x25519:<base32>
func LoadClientAuthDir(dir string, store *ClientAuthStore) (int, error) {
	if dir == "" || store == nil {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".auth_private") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		addr, key, err := parseAuthPrivate(string(data))
		if err != nil {
			continue
		}
		if err := store.AddCredential(addr, key); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

func parseAuthPrivate(s string) (string, [32]byte, error) {
	var zero [32]byte
	line := strings.TrimSpace(s)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	parts := strings.Split(line, ":")
	if len(parts) != 4 || parts[1] != "descriptor" || parts[2] != "x25519" {
		return "", zero, fmt.Errorf("invalid auth_private")
	}
	addr := parts[0]
	if !strings.HasSuffix(addr, ".onion") {
		addr += ".onion"
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(parts[3]))
	if err != nil || len(raw) != 32 {
		return "", zero, fmt.Errorf("invalid x25519 key")
	}
	var key [32]byte
	copy(key[:], raw)
	return addr, key, nil
}
