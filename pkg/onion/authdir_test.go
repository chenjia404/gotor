package onion

import (
	"encoding/base32"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientAuthDir(t *testing.T) {
	dir := t.TempDir()
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key[:])
	body := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd:descriptor:x25519:" + b32 + "\n"
	if err := os.WriteFile(filepath.Join(dir, "foo.auth_private"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewClientAuthStore()
	n, err := LoadClientAuthDir(dir, store)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !storeHas(store, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion") {
		t.Fatal("credential not stored")
	}
}

func storeHas(s *ClientAuthStore, addr string) bool {
	_, ok := s.GetCredential(addr)
	return ok
}
