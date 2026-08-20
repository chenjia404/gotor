package datadir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPaths(t *testing.T) {
	p := NewPaths("/data", "")
	if p.CacheDir != "/data" {
		t.Fatalf("cache fallback: %s", p.CacheDir)
	}
	if !strings.HasSuffix(p.Lock(), "lock") {
		t.Fatalf("lock %s", p.Lock())
	}
	if filepath.Base(p.CachedConsensus()) != CachedConsName {
		t.Fatalf("consensus %s", p.CachedConsensus())
	}
}

func TestLockExclusive(t *testing.T) {
	dir := t.TempDir()
	l1, err := TryLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l1.Unlock() }()

	if _, err := TryLock(dir); err == nil {
		t.Fatal("second lock should fail")
	}
	if err := l1.Unlock(); err != nil {
		t.Fatal(err)
	}
	l2, err := TryLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Unlock()
}

func TestPidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tor.pid")
	if err := WritePidFile(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		t.Fatalf("pidfile: %s %v", data, err)
	}
	if err := RemovePidFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pidfile should be removed")
	}
}

func TestStateRoundTrip(t *testing.T) {
	raw := []byte("TorVersion Tor 0.4.9.11 (gotor)\n" +
		"Guard in=default rsa_id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA nickname=Foo\n")
	sf := ParseState(raw)
	if len(sf.Guards) != 1 || sf.Guards[0].Nickname != "Foo" {
		t.Fatalf("guards %+v", sf.Guards)
	}
	if sf.Guards[0].RSAID != strings.Repeat("A", 40) {
		t.Fatalf("rsa %s", sf.Guards[0].RSAID)
	}
	out := sf.Serialize("Tor 0.4.9.11 (gotor)")
	again := ParseState(out)
	if len(again.Guards) != 1 || again.Guards[0].Nickname != "Foo" {
		t.Fatalf("reserialized %+v", again.Guards)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := SaveState(path, sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path)
	if err != nil || len(loaded.Guards) != 1 {
		t.Fatalf("load %v %+v", err, loaded)
	}
}

func TestStateFileGetSet(t *testing.T) {
	sf := &StateFile{}
	if _, ok := sf.Get("BWHistoryReadValues"); ok {
		t.Fatal("empty get")
	}
	sf.Set("BWHistoryReadValues", "1,2,3")
	sf.Set("GuardDummy", "keep")
	if v, ok := sf.Get("BWHistoryReadValues"); !ok || v != "1,2,3" {
		t.Fatalf("get %q %v", v, ok)
	}
	sf.Set("BWHistoryReadValues", "9")
	if v, _ := sf.Get("BWHistoryReadValues"); v != "9" {
		t.Fatalf("replace %q", v)
	}
	if v, _ := sf.Get("GuardDummy"); v != "keep" {
		t.Fatal("set 不得改其它键")
	}
}

func TestLoadStateMissing(t *testing.T) {
	sf, err := LoadState(filepath.Join(t.TempDir(), "nope"))
	if err != nil || sf == nil {
		t.Fatalf("%v %+v", err, sf)
	}
}

func TestValidRSAFingerprint(t *testing.T) {
	if !ValidRSAFingerprint(strings.Repeat("ab", 20)) {
		t.Fatal("40 hex should pass")
	}
	if !ValidRSAFingerprint("AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA") {
		t.Fatal("spaced fingerprint should pass")
	}
	if ValidRSAFingerprint("FF") || ValidRSAFingerprint("not-a-fingerprint!!!!!!!!!!!!!!") {
		t.Fatal("invalid should fail")
	}
}

func TestPrepareUnixSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ctrl.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareUnixSocket(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("stale socket should be removed")
	}
}
