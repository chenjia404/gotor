package directory

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// CachedMicrodescConsensusHistDir 存放按 FromDigest 命名的历史共识，供多小时 consdiff。
	CachedMicrodescConsensusHistDir = "cached-microdesc-consensus.hist"

	// maxConsensusHistHours 对齐 param-spec max-consensus-age-to-cache-for-diff 默认 72。
	// 仍禁止宣告 DirCache=2：缺真网被当缓存证据，且未做 ns/microdesc 分库与预压缩 diff 库。
	maxConsensusHistHours = 72
	maxConsensusHistFiles = 72
	maxOrDiffFromHashes   = 16
)

// LookupHistoricalConsensus 按 X-Or-Diff-From-Consensus /diff/<HASH> 查找历史共识。
// 先查 hist/<digest>，再回退 CacheDirectory/cached-microdesc-consensus.prev（旧缓存只有上一份）。
// currentDoc 有 valid-after 时，丢弃超过 72h 的历史（param-spec 默认）。
func LookupHistoricalConsensus(cacheDir string, hashes []string, currentDoc string) (doc, digest string, ok bool) {
	if cacheDir == "" || len(hashes) == 0 {
		return "", "", false
	}
	if len(hashes) > maxOrDiffFromHashes {
		hashes = hashes[:maxOrDiffFromHashes]
	}
	for _, h := range hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if !validSHA3Hex(h) {
			continue
		}
		if body, found := readCachedConsensusFile(cacheDir, filepath.Join(CachedMicrodescConsensusHistDir, h)); found {
			// 文件名必须等于正文 FromDigest，避免错名文件冒充客户端要的 HASH。
			if strings.ToLower(consensusDiffFromDigest(body)) == h && !consensusOlderThanMaxHist(body, currentDoc) {
				return body, h, true
			}
		}
	}
	prev, found := readCachedConsensusFile(cacheDir, cachedMicrodescConsensusPrevName)
	if !found {
		return "", "", false
	}
	from := strings.ToLower(consensusDiffFromDigest(prev))
	if consensusOlderThanMaxHist(prev, currentDoc) {
		return "", "", false
	}
	for _, h := range hashes {
		if hexDigestEqual(h, from) {
			return prev, from, true
		}
	}
	return "", "", false
}

func persistConsensusHistory(cacheDir string, outgoing []byte, newDoc string) {
	if cacheDir == "" || len(outgoing) == 0 || len(outgoing) > maxCachedConsensusBytes {
		return
	}
	oldDoc := string(outgoing)
	if consensusOlderThanMaxHist(oldDoc, newDoc) {
		pruneConsensusHistory(cacheDir, newDoc)
		dropStalePrevConsensus(cacheDir, newDoc)
		return
	}
	digest := strings.ToLower(consensusDiffFromDigest(oldDoc))
	if !validSHA3Hex(digest) {
		return
	}
	histDir := filepath.Join(cacheDir, CachedMicrodescConsensusHistDir)
	// .prev 先写：hist 失败时落后一期的客户端仍能拿 limited-ed。
	_ = writeCachedConsensusFile(cacheDir, cachedMicrodescConsensusPrevName, outgoing)
	if err := os.MkdirAll(histDir, 0o700); err != nil {
		return
	}
	if err := writeCachedConsensusFile(cacheDir, filepath.Join(CachedMicrodescConsensusHistDir, digest), outgoing); err != nil {
		return
	}
	pruneConsensusHistory(cacheDir, newDoc)
}

func pruneConsensusHistory(cacheDir, newDoc string) {
	histDir := filepath.Join(cacheDir, CachedMicrodescConsensusHistDir)
	ents, err := os.ReadDir(histDir)
	if err != nil {
		dropStalePrevConsensus(cacheDir, newDoc)
		return
	}
	type item struct {
		name string
		va   time.Time
	}
	keep := make([]item, 0, len(ents))
	for _, ent := range ents {
		name := ent.Name()
		path := filepath.Join(CachedMicrodescConsensusHistDir, name)
		if ent.IsDir() || !validSHA3Hex(name) {
			_ = removeCachedConsensusFile(cacheDir, path)
			continue
		}
		body, ok := readCachedConsensusFile(cacheDir, path)
		if !ok {
			_ = removeCachedConsensusFile(cacheDir, path)
			continue
		}
		if consensusOlderThanMaxHist(body, newDoc) {
			_ = removeCachedConsensusFile(cacheDir, path)
			continue
		}
		keep = append(keep, item{name: name, va: parseConsensusValidAfter(body)})
	}
	if len(keep) > maxConsensusHistFiles {
		// 无 valid-after 的排后面，优先丢掉。
		sort.Slice(keep, func(i, j int) bool {
			if keep[i].va.Equal(keep[j].va) {
				return keep[i].name > keep[j].name
			}
			return keep[i].va.After(keep[j].va)
		})
		for _, extra := range keep[maxConsensusHistFiles:] {
			_ = removeCachedConsensusFile(cacheDir, filepath.Join(CachedMicrodescConsensusHistDir, extra.name))
		}
	}
	dropStalePrevConsensus(cacheDir, newDoc)
}

func dropStalePrevConsensus(cacheDir, newDoc string) {
	prev, ok := readCachedConsensusFile(cacheDir, cachedMicrodescConsensusPrevName)
	if !ok {
		return
	}
	if consensusOlderThanMaxHist(prev, newDoc) {
		_ = removeCachedConsensusFile(cacheDir, cachedMicrodescConsensusPrevName)
	}
}

func consensusOlderThanMaxHist(oldDoc, newDoc string) bool {
	oldVA := parseConsensusValidAfter(oldDoc)
	newVA := parseConsensusValidAfter(newDoc)
	if oldVA.IsZero() || newVA.IsZero() {
		return false
	}
	return newVA.Sub(oldVA) > time.Duration(maxConsensusHistHours)*time.Hour
}

func parseConsensusValidAfter(doc string) time.Time {
	// valid-after 在头部；只扫前 4KiB，避免为过期判断 Split 整份共识。
	head := doc
	if len(head) > 4096 {
		head = head[:4096]
	}
	for {
		line, rest, found := strings.Cut(head, "\n")
		if strings.HasPrefix(line, "valid-after ") {
			t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(line[len("valid-after "):]), time.UTC)
			if err != nil {
				return time.Time{}
			}
			return t
		}
		if strings.HasPrefix(line, "directory-footer") || strings.HasPrefix(line, "directory-signature ") {
			return time.Time{}
		}
		if !found {
			return time.Time{}
		}
		head = rest
	}
}

func readCachedConsensusFile(cacheDir, rel string) (string, bool) {
	path, ok := safeCacheRelPath(cacheDir, rel)
	if !ok {
		return "", false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- 仅 CacheDirectory 下固定/校验过的相对路径
	if err != nil || len(data) == 0 || len(data) > maxCachedConsensusBytes {
		return "", false
	}
	return string(data), true
}

func writeCachedConsensusFile(cacheDir, rel string, data []byte) error {
	path, ok := safeCacheRelPath(cacheDir, rel)
	if !ok {
		return os.ErrInvalid
	}
	return writeFileAtomic(path, data, 0o600)
}

func removeCachedConsensusFile(cacheDir, rel string) error {
	path, ok := safeCacheRelPath(cacheDir, rel)
	if !ok {
		return os.ErrInvalid
	}
	return os.Remove(path)
}

func safeCacheRelPath(cacheDir, rel string) (string, bool) {
	if cacheDir == "" || rel == "" || strings.Contains(rel, "..") {
		return "", false
	}
	base := filepath.Clean(cacheDir)
	path := filepath.Join(base, rel)
	if !strings.HasPrefix(path, base+string(os.PathSeparator)) && path != base {
		return "", false
	}
	return path, true
}
