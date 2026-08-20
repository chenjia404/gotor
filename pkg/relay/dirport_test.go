package relay

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
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
