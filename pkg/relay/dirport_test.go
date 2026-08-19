package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
