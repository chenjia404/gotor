package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func histConsensusAt(t time.Time, marker string) string {
	va := t.UTC().Format("2006-01-02 15:04:05")
	fu := t.UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
	vu := t.UTC().Add(3 * time.Hour).Format("2006-01-02 15:04:05")
	return "" +
		"network-status-version 3\n" +
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

func TestPersistConsensusDiskKeepsMultiHourHistory(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c0 := histConsensusAt(base, "hour0")
	c1 := histConsensusAt(base.Add(time.Hour), "hour1")
	c2 := histConsensusAt(base.Add(2*time.Hour), "hour2")
	c.persistConsensusDisk(c0)
	c.persistConsensusDisk(c1)
	c.persistConsensusDisk(c2)

	d0 := strings.ToLower(consensusDiffFromDigest(c0))
	d1 := strings.ToLower(consensusDiffFromDigest(c1))
	if d0 == d1 {
		t.Fatal("testdata digests must differ")
	}

	got0, digest0, ok := LookupHistoricalConsensus(dir, []string{d0}, c2)
	if !ok || got0 != c0 || digest0 != d0 {
		t.Fatalf("落后两期应命中 hist: ok=%v digest=%s", ok, digest0)
	}
	got1, digest1, ok := LookupHistoricalConsensus(dir, []string{d1}, c2)
	if !ok || got1 != c1 || digest1 != d1 {
		t.Fatalf("上一份应命中: ok=%v digest=%s", ok, digest1)
	}

	prev, err := os.ReadFile(filepath.Join(dir, cachedMicrodescConsensusPrevName))
	if err != nil {
		t.Fatal(err)
	}
	if string(prev) != c1 {
		t.Fatalf(".prev 应是最近一份历史, got %q", prev)
	}
	if _, err := os.Stat(filepath.Join(dir, CachedMicrodescConsensusHistDir, d0)); err != nil {
		t.Fatalf("hist/%s: %v", d0, err)
	}
}

func TestPersistConsensusDiskPrunesOlderThan72h(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := histConsensusAt(base, "old")
	mid := histConsensusAt(base.Add(2*time.Hour), "mid")
	fresh := histConsensusAt(base.Add(73*time.Hour), "fresh")
	c.persistConsensusDisk(old)
	c.persistConsensusDisk(mid)
	c.persistConsensusDisk(fresh)

	if _, _, ok := LookupHistoricalConsensus(dir, []string{strings.ToLower(consensusDiffFromDigest(old))}, fresh); ok {
		t.Fatal("超过 72h 的共识不得再用于 consdiff")
	}
	if _, _, ok := LookupHistoricalConsensus(dir, []string{strings.ToLower(consensusDiffFromDigest(mid))}, fresh); !ok {
		t.Fatal("73h-2h=71h 应保留")
	}
}

func TestLookupHistoricalConsensusCapsHashList(t *testing.T) {
	dir := t.TempDir()
	doc := histConsensusAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "cap")
	digest := strings.ToLower(consensusDiffFromDigest(doc))
	if err := os.MkdirAll(filepath.Join(dir, CachedMicrodescConsensusHistDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CachedMicrodescConsensusHistDir, digest), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	hashes := make([]string, maxOrDiffFromHashes+1)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("%064x", i+1)
	}
	hashes[maxOrDiffFromHashes] = digest // 超过上限，应被截掉
	if _, _, ok := LookupHistoricalConsensus(dir, hashes, ""); ok {
		t.Fatal("超过 maxOrDiffFromHashes 的 hash 不得再查")
	}
	hashes[0] = digest
	if _, _, ok := LookupHistoricalConsensus(dir, hashes, ""); !ok {
		t.Fatal("上限内的第一个 hash 应命中")
	}
}

func TestLookupHistoricalConsensusRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	if _, _, ok := LookupHistoricalConsensus(dir, []string{"../" + strings.Repeat("a", 60)}, ""); ok {
		t.Fatal("非法 hash 不得命中")
	}
	if _, _, ok := LookupHistoricalConsensus(dir+"", nil, ""); ok {
		t.Fatal("空 hashes 不得命中")
	}
}

func TestLookupHistoricalConsensusRejectsDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	doc := histConsensusAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "real")
	fake := strings.Repeat("ab", 32)
	if err := os.MkdirAll(filepath.Join(dir, CachedMicrodescConsensusHistDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CachedMicrodescConsensusHistDir, fake), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := LookupHistoricalConsensus(dir, []string{fake}, ""); ok {
		t.Fatal("文件名与 FromDigest 不一致不得命中")
	}
}

func TestLookupHistoricalConsensusFallsBackToPrev(t *testing.T) {
	dir := t.TempDir()
	doc := histConsensusAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "only-prev")
	if err := os.WriteFile(filepath.Join(dir, cachedMicrodescConsensusPrevName), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.ToLower(consensusDiffFromDigest(doc))
	got, gotD, ok := LookupHistoricalConsensus(dir, []string{digest}, "")
	if !ok || got != doc || gotD != digest {
		t.Fatalf("只有 .prev 时也应命中: ok=%v", ok)
	}
}

func TestLookupHistoricalConsensusRejectsExpiredPrev(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := histConsensusAt(base, "stale-prev")
	curr := histConsensusAt(base.Add(80*time.Hour), "now")
	if err := os.WriteFile(filepath.Join(dir, cachedMicrodescConsensusPrevName), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.ToLower(consensusDiffFromDigest(old))
	if _, _, ok := LookupHistoricalConsensus(dir, []string{digest}, curr); ok {
		t.Fatal("过期 .prev 不得再用于 consdiff")
	}
}

func TestConsensusOlderThanMaxHistBoundary(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := histConsensusAt(base, "a")
	exact := histConsensusAt(base.Add(72*time.Hour), "b")
	over := histConsensusAt(base.Add(72*time.Hour+time.Second), "c")
	if consensusOlderThanMaxHist(old, exact) {
		t.Fatal("刚好 72h 应保留")
	}
	if !consensusOlderThanMaxHist(old, over) {
		t.Fatal("超过 72h 应丢弃")
	}
	if consensusOlderThanMaxHist("no-valid-after\n", exact) {
		t.Fatal("缺 valid-after 不得误删")
	}
}

func TestSafeCacheRelPathRejectsDotDot(t *testing.T) {
	dir := t.TempDir()
	if _, ok := safeCacheRelPath(dir, filepath.Join("..", "etc", "passwd")); ok {
		t.Fatal(".. 必须拒绝")
	}
	if _, ok := safeCacheRelPath(dir, ""); ok {
		t.Fatal("空相对路径必须拒绝")
	}
	if _, ok := safeCacheRelPath("", "cached-microdesc-consensus.prev"); ok {
		t.Fatal("空 cacheDir 必须拒绝")
	}
	if _, ok := safeCacheRelPath(dir, filepath.Join(CachedMicrodescConsensusHistDir, strings.Repeat("a", 64))); !ok {
		t.Fatal("合法 hist 相对路径应通过")
	}
}

func TestPruneConsensusHistoryDropsJunkNames(t *testing.T) {
	dir := t.TempDir()
	hist := filepath.Join(dir, CachedMicrodescConsensusHistDir)
	if err := os.MkdirAll(hist, 0o700); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(hist, "not-a-digest")
	if err := os.WriteFile(junk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pruneConsensusHistory(dir, histConsensusAt(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC), "now"))
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Fatal("非法 hist 文件名应删除")
	}
}

func TestPruneConsensusHistoryCapsFileCount(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// 直接写入超过上限的 hist 文件，避免 persist 73 次过慢。
	if err := os.MkdirAll(filepath.Join(dir, CachedMicrodescConsensusHistDir), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxConsensusHistFiles+3; i++ {
		doc := histConsensusAt(base.Add(time.Duration(i)*time.Hour), fmt.Sprintf("n%d", i))
		digest := strings.ToLower(consensusDiffFromDigest(doc))
		if err := writeCachedConsensusFile(dir, filepath.Join(CachedMicrodescConsensusHistDir, digest), []byte(doc)); err != nil {
			t.Fatal(err)
		}
	}
	newest := histConsensusAt(base.Add(time.Duration(maxConsensusHistFiles+3)*time.Hour), "curr")
	pruneConsensusHistory(dir, newest)
	ents, err := os.ReadDir(filepath.Join(dir, CachedMicrodescConsensusHistDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) > maxConsensusHistFiles {
		t.Fatalf("hist 文件数 %d 超过上限 %d", len(ents), maxConsensusHistFiles)
	}
}
