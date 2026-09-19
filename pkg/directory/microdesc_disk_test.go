package directory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMicrodescDiskLimitCoversLiveCache(t *testing.T) {
	if defaultMaxCachedMicrodescsBytes < 64<<20 {
		t.Fatalf("limit %d is below the live cached-microdescs.new size (~33MiB)", defaultMaxCachedMicrodescsBytes)
	}
}

func TestMicrodescDiskSkipsOversizedJournal(t *testing.T) {
	dir := t.TempDir()
	old := maxCachedMicrodescsBytes
	maxCachedMicrodescsBytes = 64
	t.Cleanup(func() { maxCachedMicrodescsBytes = old })

	body := []byte("onion-key\nntor-onion-key keep\n")
	if err := os.WriteFile(filepath.Join(dir, cachedMicrodescsName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cachedMicrodescsNewName), []byte(strings.Repeat("x", 65)), 0o600); err != nil {
		t.Fatal(err)
	}
	md := &microdescDiskCache{dir: dir, byDigest: map[string][]byte{}}
	if err := md.load(); err != nil {
		t.Fatal(err)
	}
	if len(md.byDigest) == 0 {
		t.Fatal("valid cached-microdescs must load when .new is oversized")
	}
	if _, err := os.Stat(filepath.Join(dir, cachedMicrodescsNewName)); !os.IsNotExist(err) {
		t.Fatal("oversized journal must be removed after a successful compact")
	}
}

func TestMicrodescDiskCompactsJournal(t *testing.T) {
	dir := t.TempDir()
	old := microdescJournalCompactAt
	microdescJournalCompactAt = 40
	t.Cleanup(func() { microdescJournalCompactAt = old })

	body := []byte("onion-key\nntor-onion-key compact\n")
	md := &microdescDiskCache{dir: dir, byDigest: map[string][]byte{}}
	md.remember(microdescriptorDigest(body), body)
	md.appendNew(body, false)
	// 第二笔把日志顶过阈值，应改写成主文件并丢掉 .new。
	md.appendNew(body, false)
	if _, err := os.Stat(filepath.Join(dir, cachedMicrodescsNewName)); !os.IsNotExist(err) {
		t.Fatalf("journal should be compacted away, stat=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, cachedMicrodescsName)); err != nil {
		t.Fatal(err)
	}

	md2 := &microdescDiskCache{dir: dir, byDigest: map[string][]byte{}}
	if err := md2.load(); err != nil {
		t.Fatal(err)
	}
	got := md2.lookup(microdescriptorDigest(body))
	if len(got) == 0 {
		t.Fatal("compacted microdesc must reload")
	}
}
