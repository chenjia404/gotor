package directory

import (
	"os"
	"path/filepath"
	"strings"
)

// 与 C Tor consdiffmgr 预压缩偏好一致：lzma → zstd → gzip → deflate。
// 文件名 <FromDigest>{,.lzma,.zst,.gz,.z}；未压缩件用于校验 hash 行与回退实时压缩。
var consdiffLibEncodings = []struct {
	enc    string
	suffix string
}{
	{"x-tor-lzma", ".lzma"},
	{"x-zstd", ".zst"},
	{"gzip", ".gz"},
	{"deflate", ".z"},
}

type consdiffHistSource struct {
	digest string
	doc    string
}

// RebuildConsensusDiffLibrary 按 hist/.prev 预计算到 current 的 limited-ed，并预压缩落盘。
// 换共识后调用；ToDigest 变了则整库重写。仍禁止据此宣告 DirCache=2。
func RebuildConsensusDiffLibrary(cacheDir string, flavor ConsensusFlavor, currentDoc string) error {
	if cacheDir == "" || strings.TrimSpace(currentDoc) == "" {
		return nil
	}
	if flavor != FlavorNS && flavor != FlavorMicrodesc {
		flavor = FlavorMicrodesc
	}
	if got, ok := DetectConsensusFlavor(currentDoc); ok && got != flavor {
		return nil
	}
	libRel := consensusDiffLibDir(flavor)
	libDir := filepath.Join(cacheDir, libRel)
	if err := os.MkdirAll(libDir, 0o700); err != nil {
		return err
	}

	toWant := strings.ToLower(ConsensusDiffToDigest(currentDoc))
	currFrom := strings.ToLower(consensusDiffFromDigest(currentDoc))
	keep := make(map[string]struct{})
	markKeep := func(digest string) {
		keep[digest] = struct{}{}
		for _, e := range consdiffLibEncodings {
			keep[digest+e.suffix] = struct{}{}
		}
	}

	for _, src := range listConsensusDiffSources(cacheDir, flavor, currentDoc) {
		if src.digest == "" || hexDigestEqual(src.digest, currFrom) {
			continue
		}
		rel := filepath.Join(libRel, src.digest)
		if existing, ok := readCachedConsensusFile(cacheDir, rel); ok {
			from, to, parsed := parseConsensusDiffHashLine(existing)
			if parsed && hexDigestEqual(from, src.digest) && hexDigestEqual(to, toWant) {
				markKeep(src.digest)
				ensureConsensusDiffCompressed(cacheDir, libRel, src.digest, []byte(existing))
				continue
			}
		}
		diff, err := GenerateConsensusDiff(src.doc, currentDoc)
		if err != nil {
			continue
		}
		if err := writeCachedConsensusFile(cacheDir, rel, []byte(diff)); err != nil {
			continue
		}
		markKeep(src.digest)
		ensureConsensusDiffCompressed(cacheDir, libRel, src.digest, []byte(diff))
	}

	ents, err := os.ReadDir(libDir)
	if err != nil {
		return nil
	}
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		if _, ok := keep[ent.Name()]; ok {
			continue
		}
		_ = removeCachedConsensusFile(cacheDir, filepath.Join(libRel, ent.Name()))
	}
	return nil
}

// TryConsensusDiffLibrary 按客户端列出的 FromDigest 取预计算 diff。
// encoding 为协商结果（gzip/deflate/x-zstd/x-tor-lzma）；有对应预压缩件则 used=encoding，
// 否则返回未压缩正文且 used=""，由调用方按需实时压缩。FPRLIST 过滤体不要走这里。
func TryConsensusDiffLibrary(cacheDir string, flavor ConsensusFlavor, hashes []string, currentDoc, encoding string) (payload []byte, used string, ok bool) {
	if cacheDir == "" || len(hashes) == 0 || strings.TrimSpace(currentDoc) == "" {
		return nil, "", false
	}
	if flavor != FlavorNS && flavor != FlavorMicrodesc {
		flavor = FlavorMicrodesc
	}
	if len(hashes) > maxOrDiffFromHashes {
		hashes = hashes[:maxOrDiffFromHashes]
	}
	toWant := strings.ToLower(ConsensusDiffToDigest(currentDoc))
	libRel := consensusDiffLibDir(flavor)
	for _, h := range hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if !validSHA3Hex(h) {
			continue
		}
		body, found := readCachedConsensusFile(cacheDir, filepath.Join(libRel, h))
		if !found {
			continue
		}
		from, to, parsed := parseConsensusDiffHashLine(body)
		if !parsed || !hexDigestEqual(from, h) || !hexDigestEqual(to, toWant) {
			continue
		}
		if suffix := consdiffEncodingSuffix(encoding); suffix != "" {
			if compressed, cok := readCachedConsensusBytes(cacheDir, filepath.Join(libRel, h+suffix)); cok {
				return compressed, encoding, true
			}
		}
		return []byte(body), "", true
	}
	return nil, "", false
}

func listConsensusDiffSources(cacheDir string, flavor ConsensusFlavor, currentDoc string) []consdiffHistSource {
	seen := make(map[string]struct{})
	var out []consdiffHistSource
	add := func(doc string) {
		if !consensusMatchesFlavor(doc, flavor) {
			return
		}
		if consensusOlderThanMaxHist(doc, currentDoc) {
			return
		}
		digest := strings.ToLower(consensusDiffFromDigest(doc))
		if !validSHA3Hex(digest) {
			return
		}
		if _, ok := seen[digest]; ok {
			return
		}
		seen[digest] = struct{}{}
		out = append(out, consdiffHistSource{digest: digest, doc: doc})
	}
	histRel := consensusHistDir(flavor)
	histDir := filepath.Join(cacheDir, histRel)
	if ents, err := os.ReadDir(histDir); err == nil {
		for _, ent := range ents {
			name := ent.Name()
			if ent.IsDir() || !validSHA3Hex(name) {
				continue
			}
			body, ok := readCachedConsensusFile(cacheDir, filepath.Join(histRel, name))
			if !ok {
				continue
			}
			if strings.ToLower(consensusDiffFromDigest(body)) != name {
				continue
			}
			add(body)
		}
	}
	if prev, ok := readCachedConsensusFile(cacheDir, consensusPrevFile(flavor)); ok {
		add(prev)
	}
	return out
}

func ensureConsensusDiffCompressed(cacheDir, libRel, digest string, uncompressed []byte) {
	for _, e := range consdiffLibEncodings {
		rel := filepath.Join(libRel, digest+e.suffix)
		if _, ok := readCachedConsensusBytes(cacheDir, rel); ok {
			continue
		}
		payload, used := CompressDirBody(e.enc, uncompressed)
		if used == "" {
			continue
		}
		_ = writeCachedConsensusFile(cacheDir, rel, payload)
	}
}

func consdiffEncodingSuffix(enc string) string {
	for _, e := range consdiffLibEncodings {
		if e.enc == enc {
			return e.suffix
		}
	}
	return ""
}

func parseConsensusDiffHashLine(diff string) (from, to string, ok bool) {
	diff = strings.TrimPrefix(diff, "\ufeff")
	ver, rest, found := strings.Cut(diff, "\n")
	if !found || !strings.HasPrefix(ver, "network-status-diff-version ") {
		return "", "", false
	}
	line, _, _ := strings.Cut(rest, "\n")
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "hash" || !validSHA3Hex(fields[1]) || !validSHA3Hex(fields[2]) {
		return "", "", false
	}
	return strings.ToLower(fields[1]), strings.ToLower(fields[2]), true
}

func readCachedConsensusBytes(cacheDir, rel string) ([]byte, bool) {
	path, ok := safeCacheRelPath(cacheDir, rel)
	if !ok {
		return nil, false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- 仅 CacheDirectory 下校验过的相对路径
	if err != nil || len(data) == 0 || len(data) > maxCachedConsensusBytes {
		return nil, false
	}
	return data, true
}
