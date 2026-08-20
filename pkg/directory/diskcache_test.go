package directory

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnableConsensusDiskCache(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	c.persistConsensusDisk("network-status-version 3\n")
	path := filepath.Join(dir, cachedMicrodescConsensusName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "network-status-version") {
		t.Fatalf("wrote %q", data)
	}

	c.SetAvoidDiskWrites(true)
	_ = os.Remove(path)
	c.persistConsensusDisk("should-not-write")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("AvoidDiskWrites should skip persist")
	}
}

func TestPersistConsensusDiskKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	first := "network-status-version 3\nfirst\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nA\n-----END SIGNATURE-----\n"
	second := "network-status-version 3\nsecond\ndirectory-signature sha256 CC DD\n-----BEGIN SIGNATURE-----\nB\n-----END SIGNATURE-----\n"
	c.persistConsensusDisk(first)
	c.persistConsensusDisk(second)

	prev := filepath.Join(dir, cachedMicrodescConsensusPrevName)
	got, err := os.ReadFile(prev)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != first {
		t.Fatalf("prev = %q", got)
	}
	curr, err := os.ReadFile(filepath.Join(dir, cachedMicrodescConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if string(curr) != second {
		t.Fatalf("curr = %q", curr)
	}

	c.persistConsensusDisk(second)
	got, err = os.ReadFile(prev)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != first {
		t.Fatal("相同共识不得覆盖 .prev")
	}
}

func TestTryLoadConsensusDiskRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, cachedMicrodescConsensusName)
	if err := os.WriteFile(path, []byte("not a consensus"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.tryLoadConsensusDisk(t.Context()); err == nil {
		t.Fatal("garbage consensus must fail verify")
	}
}

func TestMicrodescDiskCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ntor := base64.StdEncoding.EncodeToString(bytesRepeat(0x42, 32))
	ed := base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	doc := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIB\n-----END RSA PUBLIC KEY-----\n" +
		"ntor-onion-key " + ntor + "\n" +
		"id ed25519 " + ed + "\n"
	digest := microdescriptorDigest([]byte(doc))

	annotated := "@last-listed 2026-01-01 00:00:00\n" + doc
	if err := os.WriteFile(filepath.Join(dir, cachedMicrodescsName), []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewClient(nil)
	if err := c.EnableMicrodescDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	relay := &Relay{Nickname: "DiskMD", MicrodescDigest: digest}
	needed := c.applyMicrodescsFromDisk([]*Relay{relay})
	if len(needed) != 0 {
		t.Fatalf("should fill from disk, leftover %d", len(needed))
	}
	if len(relay.NtorOnionKey) != 32 {
		t.Fatal("ntor not applied from disk")
	}

	// persistFetched 应跳过已有 digest；新 raw 追加 .new
	relay2 := &Relay{Nickname: "New", MicrodescDigest: "not-in-cache", NtorOnionKey: bytesRepeat(0x11, 32), microdescRaw: []byte(doc)}
	c.persistFetchedMicrodescs([]*Relay{relay2})
	if _, err := os.Stat(filepath.Join(dir, cachedMicrodescsNewName)); err != nil {
		t.Fatalf(".new: %v", err)
	}
}

func TestStripAnnotationLines(t *testing.T) {
	in := []byte("@last-listed 2026-01-01 00:00:00\nonion-key\nfoo\n")
	out := string(stripAnnotationLines(in))
	if strings.Contains(out, "@") {
		t.Fatalf("annotation remained: %q", out)
	}
	if !strings.Contains(out, "onion-key") {
		t.Fatalf("body lost: %q", out)
	}
}
