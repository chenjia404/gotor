package relay

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCTorKeyFilenames(t *testing.T) {
	dir := t.TempDir()
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_master_id_secret_key"), encodeCTorEd25519Secret(keys.Ed25519Private), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := keys.SaveKeys(tmp); err != nil {
		t.Fatal(err)
	}
	rsa, err := os.ReadFile(filepath.Join(tmp, "secret_id_key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret_id_key"), rsa, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint() != keys.Fingerprint() {
		t.Fatal("C Tor 文件名加载后指纹应相同")
	}
	if !bytes.Equal(loaded.Ed25519Private, keys.Ed25519Private) {
		t.Fatal("Ed25519 身份应相同")
	}
}

func TestParseTaggedNtor(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	tagged := encodeCTorNtorSecret(key)
	got, err := parseNtorSecret(tagged)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("tagged ntor 解析失败")
	}
	raw, err := parseNtorSecret(key)
	if err != nil || !bytes.Equal(raw, key) {
		t.Fatal("裸 32 字节 ntor 应可用")
	}
}

func TestParseTaggedEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tagged := encodeCTorEd25519Secret(priv)
	got, err := parseEd25519Secret(tagged)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, priv) {
		t.Fatal("tagged 解析失败")
	}
}
