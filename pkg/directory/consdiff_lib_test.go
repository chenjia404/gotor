package directory

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
)

func testLibConsensusAt(flavor ConsensusFlavor, ts time.Time, marker string) string {
	head := "network-status-version 3\n"
	if flavor == FlavorMicrodesc {
		head = "network-status-version 3 microdesc\n"
	}
	va := ts.UTC().Format("2006-01-02 15:04:05")
	fu := ts.UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
	vu := ts.UTC().Add(3 * time.Hour).Format("2006-01-02 15:04:05")
	return head +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"valid-after " + va + "\n" +
		"fresh-until " + fu + "\n" +
		"valid-until " + vu + "\n" +
		"marker " + marker + "\n" +
		"directory-footer\n" +
		"directory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\n" +
		marker + "\n-----END SIGNATURE-----\n"
}

func writeLibHist(t *testing.T, cacheDir string, flavor ConsensusFlavor, doc string) string {
	t.Helper()
	digest := strings.ToLower(ConsensusDiffFromDigest(doc))
	hist := filepath.Join(cacheDir, consensusHistDir(flavor))
	if err := os.MkdirAll(hist, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hist, digest), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, consensusPrevFile(flavor)), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestRebuildConsensusDiffLibraryPrecompresses(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := testLibConsensusAt(FlavorMicrodesc, base, "old")
	curr := testLibConsensusAt(FlavorMicrodesc, base.Add(time.Hour), "new")
	from := writeLibHist(t, dir, FlavorMicrodesc, old)
	if err := os.WriteFile(filepath.Join(dir, ConsensusCacheFile(FlavorMicrodesc)), []byte(curr), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RebuildConsensusDiffLibrary(dir, FlavorMicrodesc, curr); err != nil {
		t.Fatal(err)
	}

	want, err := GenerateConsensusDiff(old, curr)
	if err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(dir, ConsensusDiffLibraryDir(FlavorMicrodesc))
	got, err := os.ReadFile(filepath.Join(lib, from))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatal("未压缩库必须等于 GenerateConsensusDiff")
	}

	payload, used, ok := TryConsensusDiffLibrary(dir, FlavorMicrodesc, []string{from}, curr, "gzip")
	if !ok || used != "gzip" {
		t.Fatalf("gzip 预压缩件应命中, ok=%v used=%q", ok, used)
	}
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil || string(plain) != want {
		t.Fatalf("gzip 解压后须为 limited-ed: %v", err)
	}

	for _, enc := range []string{"deflate", "x-zstd", "x-tor-lzma"} {
		p, u, hit := TryConsensusDiffLibrary(dir, FlavorMicrodesc, []string{from}, curr, enc)
		if !hit || u != enc {
			t.Fatalf("%s 预压缩件应命中, ok=%v used=%q", enc, hit, u)
		}
		if string(mustDecompressDir(t, enc, p)) != want {
			t.Fatalf("%s 解压后须为同一 limited-ed", enc)
		}
	}

	plainPayload, used, ok := TryConsensusDiffLibrary(dir, FlavorMicrodesc, []string{from}, curr, "")
	if !ok || used != "" || string(plainPayload) != want {
		t.Fatal("无 Accept-Encoding 应出未压缩库")
	}
}

func TestRebuildConsensusDiffLibraryPrunesStaleAndSkipsExpired(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := testLibConsensusAt(FlavorMicrodesc, base, "keep")
	stale := testLibConsensusAt(FlavorMicrodesc, base.Add(-73*time.Hour), "stale")
	curr := testLibConsensusAt(FlavorMicrodesc, base.Add(time.Hour), "curr")
	keepFrom := writeLibHist(t, dir, FlavorMicrodesc, old)
	staleFrom := strings.ToLower(ConsensusDiffFromDigest(stale))
	hist := filepath.Join(dir, CachedMicrodescConsensusHistDir)
	if err := os.WriteFile(filepath.Join(hist, staleFrom), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(dir, CachedMicrodescConsensusDiffDir)
	if err := os.MkdirAll(lib, 0o700); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(lib, strings.Repeat("a", 64))
	if err := os.WriteFile(junk, []byte("stale-diff"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RebuildConsensusDiffLibrary(dir, FlavorMicrodesc, curr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Fatal("ToDigest 已变的旧库文件必须删掉")
	}
	if _, err := os.Stat(filepath.Join(lib, staleFrom)); !os.IsNotExist(err) {
		t.Fatal("超过 72h 的历史不得进 diff 库")
	}
	if _, err := os.Stat(filepath.Join(lib, keepFrom)); err != nil {
		t.Fatal("72h 内历史必须进库")
	}
}

func TestPersistConsensusDiskRebuildsDiffLibrary(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	first := testLibConsensusAt(FlavorMicrodesc, base, "p0")
	second := testLibConsensusAt(FlavorMicrodesc, base.Add(time.Hour), "p1")
	c.persistConsensusDisk(first)
	c.persistConsensusDisk(second)

	from := strings.ToLower(ConsensusDiffFromDigest(first))
	want, err := GenerateConsensusDiff(first, second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, CachedMicrodescConsensusDiffDir, from))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatal("persist 换共识后必须同步写出 limited-ed 库")
	}
}

func TestTryConsensusDiffLibraryRejectsWrongFlavorAndUnknownHash(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := testLibConsensusAt(FlavorMicrodesc, base, "md")
	curr := testLibConsensusAt(FlavorMicrodesc, base.Add(time.Hour), "md2")
	from := writeLibHist(t, dir, FlavorMicrodesc, old)
	if err := RebuildConsensusDiffLibrary(dir, FlavorMicrodesc, curr); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := TryConsensusDiffLibrary(dir, FlavorNS, []string{from}, curr, ""); ok {
		t.Fatal("ns 库不得命中 microdesc 预计算件")
	}
	if _, _, ok := TryConsensusDiffLibrary(dir, FlavorMicrodesc, []string{strings.Repeat("f", 64)}, curr, ""); ok {
		t.Fatal("未知 FromDigest 不得命中")
	}
}

func TestConsensusDiffToDigestMatchesGenerate(t *testing.T) {
	old := testLibConsensusAt(FlavorNS, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "a")
	curr := testLibConsensusAt(FlavorNS, time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC), "b")
	diff, err := GenerateConsensusDiff(old, curr)
	if err != nil {
		t.Fatal(err)
	}
	_, to, ok := parseConsensusDiffHashLine(diff)
	if !ok {
		t.Fatal("hash 行")
	}
	if to != strings.ToLower(ConsensusDiffToDigest(curr)) {
		t.Fatal("ToDigest 必须与 GenerateConsensusDiff 第二行一致")
	}
}

func mustDecompressDir(t *testing.T, enc string, payload []byte) []byte {
	t.Helper()
	switch enc {
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = zr.Close() }()
		b, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		return b
	case "x-zstd":
		zr, err := zstd.NewReader(bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		b, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		return b
	case "x-tor-lzma":
		if len(payload) >= 6 && bytes.Equal(payload[:6], []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}) {
			t.Fatal("lzma 不得使用 xz 容器")
		}
		lr, err := lzma.NewReader(bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(lr)
		if err != nil {
			t.Fatal(err)
		}
		return b
	default:
		t.Fatalf("unknown enc %s", enc)
		return nil
	}
}
