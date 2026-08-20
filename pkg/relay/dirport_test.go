package relay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/onion"
	"github.com/ulikunitz/xz/lzma"
)

func TestDirCacheServesCachedConsensus(t *testing.T) {
	dir := t.TempDir()
	body := []byte("network-status-version 3\n")
	if err := os.WriteFile(filepath.Join(dir, "cached-microdesc-consensus"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)
	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	got, _ := io.ReadAll(rec.Body)
	if string(got) != string(body) {
		t.Fatalf("got %q", got)
	}
}

func TestDirCacheMissingIs404(t *testing.T) {
	s := NewDirCacheServer(t.TempDir(), nil)
	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

const (
	testAuthFP1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testAuthFP2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func testCachedCerts() string {
	return "" +
		"dir-key-certificate-version 3\n" +
		"fingerprint " + testAuthFP1 + "\n" +
		"dir-key-published 2026-01-01 00:00:00\n" +
		"dir-key-expires 2027-01-01 00:00:00\n" +
		"dir-key-certificate-version 3\n" +
		"fingerprint " + testAuthFP2 + "\n" +
		"dir-key-published 2026-01-01 00:00:00\n" +
		"dir-key-expires 2027-01-01 00:00:00\n"
}

func TestDirCacheServesKeysByFingerprint(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cached-certs"), []byte(testCachedCerts()), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)

	t.Run("single", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tor/keys/fp/"+testAuthFP1, http.NoBody)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "fingerprint "+testAuthFP1) {
			t.Fatalf("missing fp1: %q", body)
		}
		if strings.Contains(body, testAuthFP2) {
			t.Fatalf("must not include other certs: %q", body)
		}
	})

	t.Run("plus_concat", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tor/keys/fp/"+testAuthFP2+"+"+testAuthFP1, http.NoBody)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, testAuthFP1) || !strings.Contains(body, testAuthFP2) {
			t.Fatalf("want both certs: %q", body)
		}
	})

	t.Run("all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tor/keys/all", http.NoBody)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if rec.Body.String() != testCachedCerts() {
			t.Fatalf("got %q", rec.Body.String())
		}
	})

	t.Run("unknown_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tor/keys/fp/FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", http.NoBody)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("invalid_path_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tor/keys/fp/../cached-certs", http.NoBody)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("path traversal must not serve 200, got %d body %q", rec.Code, rec.Body.String())
		}
	})
}

func testConsensusPair() (prev, curr string) {
	prev = "" +
		"network-status-version 3\n" +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"valid-after 2024-01-01 00:00:00\n" +
		"fresh-until 2024-01-01 01:00:00\n" +
		"valid-until 2024-01-01 03:00:00\n" +
		"directory-footer\n" +
		"directory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nOLD\n-----END SIGNATURE-----\n"
	curr = "" +
		"network-status-version 3\n" +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"valid-after 2024-01-01 01:00:00\n" +
		"fresh-until 2024-01-01 02:00:00\n" +
		"valid-until 2024-01-01 04:00:00\n" +
		"directory-footer\n" +
		"directory-signature sha256 CC DD\n-----BEGIN SIGNATURE-----\nNEW\n-----END SIGNATURE-----\n"
	return prev, curr
}

func writeConsensusPair(t *testing.T, dir string) (prev, curr string) {
	t.Helper()
	prev, curr = testConsensusPair()
	if err := os.WriteFile(filepath.Join(dir, cachedConsensusName), []byte(curr), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cachedConsensusPrevName), []byte(prev), 0o600); err != nil {
		t.Fatal(err)
	}
	return prev, curr
}

func TestDirCacheServesConsensusDiffHeader(t *testing.T) {
	dir := t.TempDir()
	prev, curr := writeConsensusPair(t, dir)
	s := NewDirCacheServer(dir, nil)

	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req.Header.Set("X-Or-Diff-From-Consensus", directory.ConsensusDiffFromDigest(prev))
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	want, err := directory.GenerateConsensusDiff(prev, curr)
	if err != nil {
		t.Fatal(err)
	}
	if body != want {
		t.Fatalf("served diff 必须与 GenerateConsensusDiff 一致")
	}
}

func TestDirCacheUnknownDiffHashFallsBackToFull(t *testing.T) {
	dir := t.TempDir()
	_, curr := writeConsensusPair(t, dir)
	s := NewDirCacheServer(dir, nil)

	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req.Header.Set("X-Or-Diff-From-Consensus", strings.Repeat("f", 64))
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Body.String() != curr {
		t.Fatalf("未知 hash 应回整份共识")
	}
}

func testConsensusAt(ts time.Time, marker string) string {
	va := ts.UTC().Format("2006-01-02 15:04:05")
	fu := ts.UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
	vu := ts.UTC().Add(3 * time.Hour).Format("2006-01-02 15:04:05")
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

func TestDirCacheServesDiffFromTwoPeriodsAgo(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	old := testConsensusAt(base, "p0")
	mid := testConsensusAt(base.Add(time.Hour), "p1")
	curr := testConsensusAt(base.Add(2*time.Hour), "p2")
	if err := os.MkdirAll(filepath.Join(dir, directory.CachedMicrodescConsensusHistDir), 0o700); err != nil {
		t.Fatal(err)
	}
	writeHist := func(doc string) {
		t.Helper()
		digest := strings.ToLower(directory.ConsensusDiffFromDigest(doc))
		path := filepath.Join(dir, directory.CachedMicrodescConsensusHistDir, digest)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeHist(old)
	writeHist(mid)
	if err := os.WriteFile(filepath.Join(dir, cachedConsensusPrevName), []byte(mid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cachedConsensusName), []byte(curr), 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewDirCacheServer(dir, nil)
	hash := directory.ConsensusDiffFromDigest(old)
	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req.Header.Set("X-Or-Diff-From-Consensus", hash)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	want, err := directory.GenerateConsensusDiff(old, curr)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Body.String() != want {
		t.Fatal("落后两期必须回 old→current 的 limited-ed，而不是整份或只认 .prev")
	}

	urlRec := httptest.NewRecorder()
	s.handler().ServeHTTP(urlRec, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/diff/"+hash+"/all", http.NoBody))
	if urlRec.Code != http.StatusOK || urlRec.Body.String() != want {
		t.Fatalf("/diff/ 落后两期应 200 limited-ed, got %d", urlRec.Code)
	}

	// 中间一份也应能 diff。
	midHash := directory.ConsensusDiffFromDigest(mid)
	midWant, err := directory.GenerateConsensusDiff(mid, curr)
	if err != nil {
		t.Fatal(err)
	}
	midReq := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	midReq.Header.Set("X-Or-Diff-From-Consensus", midHash)
	midRec := httptest.NewRecorder()
	s.handler().ServeHTTP(midRec, midReq)
	if midRec.Body.String() != midWant {
		t.Fatal("上一份历史也必须能生成 limited-ed")
	}

	// 超过 72h 的 hist 即使文件还在，对外也不得再出 diff。
	stale := testConsensusAt(base.Add(-73*time.Hour), "too-old")
	staleHash := directory.ConsensusDiffFromDigest(stale)
	writeHist(stale)
	staleReq := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	staleReq.Header.Set("X-Or-Diff-From-Consensus", staleHash)
	staleRec := httptest.NewRecorder()
	s.handler().ServeHTTP(staleRec, staleReq)
	if staleRec.Body.String() != curr {
		t.Fatal("过期历史必须回整份当前共识，不得出 limited-ed")
	}
	staleURL := httptest.NewRecorder()
	s.handler().ServeHTTP(staleURL, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/diff/"+staleHash+"/all", http.NoBody))
	if staleURL.Code != http.StatusNotFound {
		t.Fatalf("过期 /diff/ 应为 404, got %d", staleURL.Code)
	}
}

func TestDirCacheConsensusDiffCachedOnSecondHit(t *testing.T) {
	dir := t.TempDir()
	prev, curr := writeConsensusPair(t, dir)
	s := NewDirCacheServer(dir, nil)
	hash := directory.ConsensusDiffFromDigest(prev)
	want, err := directory.GenerateConsensusDiff(prev, curr)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
		req.Header.Set("X-Or-Diff-From-Consensus", hash)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		if rec.Body.String() != want {
			t.Fatalf("第 %d 次应命中同一 limited-ed", i+1)
		}
	}
}

func TestDirCacheServesConsensusDiffURL(t *testing.T) {
	dir := t.TempDir()
	prev, _ := writeConsensusPair(t, dir)
	s := NewDirCacheServer(dir, nil)
	hash := directory.ConsensusDiffFromDigest(prev)

	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/diff/"+hash+"/all", http.NoBody)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Body.String(), "network-status-diff-version 1\n") {
		t.Fatalf("want limited-ed")
	}

	bad := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/diff/"+strings.Repeat("0", 64)+"/all", http.NoBody)
	badRec := httptest.NewRecorder()
	s.handler().ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusNotFound {
		t.Fatalf("未知 hash 的 /diff/ 应为 404, got %d", badRec.Code)
	}

	trav := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/diff/../cached-microdesc-consensus", http.NoBody)
	travRec := httptest.NewRecorder()
	s.handler().ServeHTTP(travRec, trav)
	if travRec.Code == http.StatusOK && strings.Contains(travRec.Body.String(), "network-status-version") {
		t.Fatal("path traversal must not serve consensus")
	}
}

func TestDirCacheFPRLISTFiltersSignatures(t *testing.T) {
	dir := t.TempDir()
	a := "aaaaaaaaaa1111111111aaaaaaaaaa1111111111"
	b := "bbbbbbbbbb2222222222bbbbbbbbbb2222222222"
	c := "cccccccccccccccccccccccccccccccccccccccc"
	z := "ffffffffffffffffffffffffffffffffffffffff"
	curr := "" +
		"network-status-version 3\n" +
		"vote-status consensus\n" +
		"valid-after 2024-01-01 01:00:00\n" +
		"directory-footer\n" +
		"directory-signature sha256 " + strings.ToUpper(a) + " SA\n-----BEGIN SIGNATURE-----\nA\n-----END SIGNATURE-----\n" +
		"directory-signature sha256 " + strings.ToUpper(b) + " SB\n-----BEGIN SIGNATURE-----\nB\n-----END SIGNATURE-----\n" +
		"directory-signature sha256 " + strings.ToUpper(c) + " SC\n-----BEGIN SIGNATURE-----\nC\n-----END SIGNATURE-----\n"
	if err := os.WriteFile(filepath.Join(dir, cachedConsensusName), []byte(curr), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)

	okURL := "/tor/status-vote/current/consensus-microdesc/" + a[:6] + "+" + b[:6]
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, okURL, http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("过半签名应 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, strings.ToUpper(a)) || !strings.Contains(body, strings.ToUpper(b)) {
		t.Fatal("必须保留请求权威的签名")
	}
	if strings.Contains(body, strings.ToUpper(c)) {
		t.Fatal("未请求的权威签名必须去掉")
	}

	fail := httptest.NewRecorder()
	s.handler().ServeHTTP(fail, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/"+a[:6]+"+"+z[:6], http.NoBody))
	if fail.Code != http.StatusNotFound {
		t.Fatalf("未过半必须 404, got %d", fail.Code)
	}

	bad := httptest.NewRecorder()
	s.handler().ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/not-hex", http.NoBody))
	if bad.Code != http.StatusNotFound {
		t.Fatalf("非法 FPRLIST 必须 404, got %d", bad.Code)
	}

	plain := httptest.NewRecorder()
	s.handler().ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody))
	if plain.Code != http.StatusOK || !strings.Contains(plain.Body.String(), strings.ToUpper(c)) {
		t.Fatal("无 FPRLIST 必须回全部签名")
	}

	// 过滤后的共识不实时 LZMA（避免无鉴权 DirPort 被滚动 FPRLIST 拖垮）。
	lz := httptest.NewRequest(http.MethodGet, okURL, http.NoBody)
	lz.Header.Set("Accept-Encoding", "x-tor-lzma, x-zstd")
	lzRec := httptest.NewRecorder()
	s.handler().ServeHTTP(lzRec, lz)
	if lzRec.Header().Get("Content-Encoding") != "x-zstd" {
		t.Fatalf("FPRLIST 过滤体应回退 zstd, got %q", lzRec.Header().Get("Content-Encoding"))
	}

	// 过滤请求不得为每个 FPRLIST 实时 GenerateConsensusDiff（未鉴权 CPU 放大）。
	prev := strings.Replace(curr, "01:00:00", "00:00:00", 1)
	prev = strings.Replace(prev, "\nA\n", "\nOLD\n", 1)
	if err := os.WriteFile(filepath.Join(dir, cachedConsensusPrevName), []byte(prev), 0o600); err != nil {
		t.Fatal(err)
	}
	diffReq := httptest.NewRequest(http.MethodGet, okURL, http.NoBody)
	diffReq.Header.Set("X-Or-Diff-From-Consensus", directory.ConsensusDiffFromDigest(prev))
	diffRec := httptest.NewRecorder()
	s.handler().ServeHTTP(diffRec, diffReq)
	if strings.HasPrefix(diffRec.Body.String(), "network-status-diff-version") {
		t.Fatal("FPRLIST 不得回 limited-ed")
	}
	if !strings.Contains(diffRec.Body.String(), strings.ToUpper(a)) || strings.Contains(diffRec.Body.String(), strings.ToUpper(c)) {
		t.Fatal("FPRLIST+Diff 头应回过滤后的整份共识")
	}
}

func TestDirCacheConsensusDiffViaBeginDir(t *testing.T) {
	dir := t.TempDir()
	prev, _ := writeConsensusPair(t, dir)
	s := NewDirCacheServer(dir, nil)
	conn, err := s.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hash := directory.ConsensusDiffFromDigest(prev)
	req := "GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\n" +
		"X-Or-Diff-From-Consensus: " + hash + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "network-status-diff-version 1\n") {
		t.Fatalf("BEGIN_DIR 应返回 limited-ed: %q", body)
	}
}

func TestDirCacheKeysFPViaBeginDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cached-certs"), []byte(testCachedCerts()), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)
	conn, err := s.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "GET /tor/keys/fp/" + testAuthFP2 + " HTTP/1.0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), testAuthFP2) {
		t.Fatalf("BEGIN_DIR body missing fp2: %q", body)
	}
}

func TestDirCacheGzipAndNotModified(t *testing.T) {
	dir := t.TempDir()
	body := []byte("network-status-version 3\nvalid-after 2024-01-01 01:00:00\nconsensus-gzip-test\n")
	path := filepath.Join(dir, "cached-microdesc-consensus")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)

	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gzip status %d", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("encoding %q", rec.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil || string(got) != string(body) {
		t.Fatalf("gzip body %q %v", got, err)
	}
	va := time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC)
	if rec.Header().Get("Last-Modified") != va.Format(http.TimeFormat) {
		t.Fatalf("Last-Modified 须用 valid-after，got %q", rec.Header().Get("Last-Modified"))
	}

	req2 := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req2.Header.Set("If-Modified-Since", va.Format(http.TimeFormat))
	rec2 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("IMS=valid-after 应为 304, got %d", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Fatal("304 不得带正文")
	}

	req3 := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req3.Header.Set("If-Modified-Since", "not-a-date")
	rec3 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("坏 IMS 应忽略, got %d", rec3.Code)
	}

	older := va.Add(-time.Hour).Format(http.TimeFormat)
	req4 := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req4.Header.Set("If-Modified-Since", older)
	rec4 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("更早的 IMS 应 200, got %d", rec4.Code)
	}
}

func TestDirCacheDotZIsDeflate(t *testing.T) {
	dir := t.TempDir()
	body := []byte("network-status-version 3\ndot-z\n")
	if err := os.WriteFile(filepath.Join(dir, "cached-microdesc-consensus"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)
	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc.z", http.NoBody)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf(".z 无 Accept-Encoding 不得带 Content-Encoding, got %q", rec.Header().Get("Content-Encoding"))
	}
	zr, err := zlib.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil || string(got) != string(body) {
		t.Fatalf("deflate body %q %v", got, err)
	}
}

func TestDirCacheHSDirPublishAndFetch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, blinded, err := onion.BuildSignedHSDescriptor(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(t.TempDir(), nil)
	pub := httptest.NewRequest(http.MethodPost, "/tor/hs/3/publish", strings.NewReader(string(raw)))
	pubRec := httptest.NewRecorder()
	s.handler().ServeHTTP(pubRec, pub)
	if pubRec.Code != http.StatusOK {
		t.Fatalf("publish %d", pubRec.Code)
	}
	path := "/tor/hs/3/" + base64.RawStdEncoding.EncodeToString(blinded)
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch %d", rec.Code)
	}
	if rec.Body.String() != string(raw) {
		t.Fatal("GET 必须回同一份外层描述符")
	}
	miss := httptest.NewRequest(http.MethodGet, "/tor/hs/3/"+base64.RawStdEncoding.EncodeToString(bytesRepeatDir(0x09, 32)), http.NoBody)
	missRec := httptest.NewRecorder()
	s.handler().ServeHTTP(missRec, miss)
	if missRec.Code != http.StatusNotFound {
		t.Fatalf("unknown blinded id should 404, got %d", missRec.Code)
	}
}

func TestDirCacheHSDirRejectsTamperAndStaleRevision(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw1, blinded, err := onion.BuildSignedHSDescriptorAtRevision(priv, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw3, _, err := onion.BuildSignedHSDescriptorAtRevision(priv, 3)
	if err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(t.TempDir(), nil)
	post := func(body []byte) int {
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tor/hs/3/publish", strings.NewReader(string(body))))
		return rec.Code
	}
	if post(raw1) != http.StatusOK {
		t.Fatal("rev=1 应接受")
	}
	tampered := append([]byte(nil), raw1...)
	idx := bytes.Index(tampered, []byte("revision-counter"))
	if idx < 0 {
		t.Fatal("no revision-counter")
	}
	tampered[idx] ^= 0x01
	if post(tampered) != http.StatusBadRequest {
		t.Fatal("篡改正文必须拒绝")
	}
	if post(raw3) != http.StatusOK {
		t.Fatal("更高 revision 应覆盖")
	}
	if post(raw1) != http.StatusBadRequest {
		t.Fatal("更低 revision 不得回滚")
	}
	path := "/tor/hs/3/" + base64.RawStdEncoding.EncodeToString(blinded)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))
	if rec.Code != http.StatusOK || rec.Body.String() != string(raw3) {
		t.Fatalf("GET 必须仍是 rev=3, status=%d", rec.Code)
	}
	locked := append(append([]byte(nil), raw3...), []byte("\nrevision-counter 999999\n")...)
	if post(locked) != http.StatusBadRequest {
		t.Fatal("未签名尾部抬高 revision 不得覆盖")
	}
}

func bytesRepeatDir(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestDirCacheDotZWithAcceptEncodingGzip(t *testing.T) {
	dir := t.TempDir()
	body := []byte("network-status-version 3\ndot-z-gzip\n")
	if err := os.WriteFile(filepath.Join(dir, "cached-microdesc-consensus"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)
	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc.z", http.NoBody)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf(".z+Accept-Encoding 应按协商编码, got %q", rec.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil || string(got) != string(body) {
		t.Fatalf("gzip body %q %v", got, err)
	}
}

func TestDirCacheZstdAndLzma(t *testing.T) {
	dir := t.TempDir()
	body := []byte("network-status-version 3\nzstd-lzma-test\n")
	if err := os.WriteFile(filepath.Join(dir, "cached-microdesc-consensus"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)

	req := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req.Header.Set("Accept-Encoding", "x-zstd")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("x-zstd status %d", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "x-zstd" {
		t.Fatalf("encoding %q", rec.Header().Get("Content-Encoding"))
	}
	zr, err := zstd.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	zr.Close()
	if err != nil || string(got) != string(body) {
		t.Fatalf("x-zstd body %q %v", got, err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req2.Header.Set("Accept-Encoding", "x-tor-lzma")
	rec2 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("x-tor-lzma status %d", rec2.Code)
	}
	if rec2.Header().Get("Content-Encoding") != "x-tor-lzma" {
		t.Fatalf("encoding %q", rec2.Header().Get("Content-Encoding"))
	}
	compressed := rec2.Body.Bytes()
	// xz 魔数 FD 37 7A 58 5A 00；官方客户端按 LZMA Alone 解，不能发 xz。
	if len(compressed) >= 3 && compressed[0] == 0xfd && compressed[1] == 0x37 && compressed[2] == 0x7a {
		t.Fatal("x-tor-lzma 不得使用 xz 容器")
	}
	lr, err := lzma.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	got2, err := io.ReadAll(lr)
	if err != nil || string(got2) != string(body) {
		t.Fatalf("x-tor-lzma body %q %v", got2, err)
	}

	// 官方客户端常一次列出全部算法；须优先 x-tor-lzma，不得退回 gzip。
	req3 := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody)
	req3.Header.Set("Accept-Encoding", "identity, deflate, gzip, x-tor-lzma, x-zstd")
	rec3 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec3, req3)
	if rec3.Header().Get("Content-Encoding") != "x-tor-lzma" {
		t.Fatalf("多算法应优先 x-tor-lzma, got %q", rec3.Header().Get("Content-Encoding"))
	}

	// 非共识文档不应走 lzma（dir-spec 只 SHOULD 用于 consensus / consdiff）。
	if err := os.WriteFile(filepath.Join(dir, "cached-certs"), []byte("dir-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req4 := httptest.NewRequest(http.MethodGet, "/tor/keys/all", http.NoBody)
	req4.Header.Set("Accept-Encoding", "identity, deflate, gzip, x-tor-lzma, x-zstd")
	rec4 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec4, req4)
	if rec4.Header().Get("Content-Encoding") != "x-zstd" {
		t.Fatalf("非共识应跳过 lzma 用 zstd, got %q", rec4.Header().Get("Content-Encoding"))
	}

	// FPRLIST 过滤体不得实时 LZMA，应退回 x-zstd。
	a := "aaaaaaaaaa1111111111aaaaaaaaaa1111111111"
	b := "bbbbbbbbbb2222222222bbbbbbbbbb2222222222"
	filtered := "" +
		"network-status-version 3\n" +
		"vote-status consensus\n" +
		"valid-after 2024-01-01 01:00:00\n" +
		"directory-footer\n" +
		"directory-signature sha256 " + strings.ToUpper(a) + " SA\n-----BEGIN SIGNATURE-----\nA\n-----END SIGNATURE-----\n" +
		"directory-signature sha256 " + strings.ToUpper(b) + " SB\n-----BEGIN SIGNATURE-----\nB\n-----END SIGNATURE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "cached-microdesc-consensus"), []byte(filtered), 0o600); err != nil {
		t.Fatal(err)
	}
	req5 := httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc/"+a[:6]+"+"+b[:6], http.NoBody)
	req5.Header.Set("Accept-Encoding", "x-tor-lzma, x-zstd")
	rec5 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusOK {
		t.Fatalf("FPRLIST+lzma status %d", rec5.Code)
	}
	if rec5.Header().Get("Content-Encoding") != "x-zstd" {
		t.Fatalf("过滤体不得实时 x-tor-lzma, got %q", rec5.Header().Get("Content-Encoding"))
	}
}
