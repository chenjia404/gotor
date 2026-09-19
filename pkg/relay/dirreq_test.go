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
	"time"

	"github.com/opd-ai/go-tor/pkg/directory"
)

type dirreqClock struct{ t time.Time }

func (c *dirreqClock) Now() time.Time { return c.t }

func TestRoundUp4(t *testing.T) {
	if roundUp4(0) != 0 || roundUp4(1) != 4 || roundUp4(4) != 4 || roundUp4(5) != 8 {
		t.Fatalf("roundUp4: 0=%d 1=%d 4=%d 5=%d", roundUp4(0), roundUp4(1), roundUp4(4), roundUp4(5))
	}
}

func TestIsV3NetworkStatusPath(t *testing.T) {
	if !isV3NetworkStatusPath("/tor/status-vote/current/consensus") {
		t.Fatal("ns consensus")
	}
	if !isV3NetworkStatusPath("/tor/status-vote/current/consensus-microdesc.z") {
		t.Fatal("microdesc .z")
	}
	if !isV3NetworkStatusPath("/tor/status-vote/current/consensus/diff/abc") {
		t.Fatal("diff")
	}
	if isV3NetworkStatusPath("/tor/micro/all") || isV3NetworkStatusPath("/tor/keys/all") {
		t.Fatal("非网络状态路径不得计入")
	}
}

func TestDirReqOmitsIncompleteDay(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	s.NoteHTTP(http.StatusOK, false)
	clk.t = clk.t.Add(23 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("未满 24h 不得写 dirreq: %v", got)
	}
}

func TestDirReqOmitsEmptyDay(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	clk.t = clk.t.Add(24 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("无请求不得写 dirreq: %v", got)
	}
}

func TestDirReqEmitsAfter24h(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	s.NoteHTTP(http.StatusOK, false)
	s.NoteHTTP(http.StatusNotFound, false)
	s.NoteHTTP(http.StatusNotModified, false)
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	end := got["dirreq-stats-end"]
	if end != "2026-09-20 12:00:00 (86400 s)" {
		t.Fatalf("dirreq-stats-end: %q", end)
	}
	resp := got["dirreq-v3-resp"]
	if !strings.Contains(resp, "served=4") || !strings.Contains(resp, "ok=4") {
		t.Fatalf("200 应进 served/ok 并向上取 4: %q", resp)
	}
	if !strings.Contains(resp, "not-found=4") || !strings.Contains(resp, "not-modified=4") {
		t.Fatalf("404/304: %q", resp)
	}
	if got["dirreq-v3-direct-dl"] != "complete=1" {
		t.Fatalf("200 DirPort 应写 complete=1: %q", got["dirreq-v3-direct-dl"])
	}
	if _, ok := got["dirreq-v3-tunneled-dl"]; ok {
		t.Fatalf("无 BEGIN_DIR 不得写 tunneled-dl: %v", got)
	}
}

func TestDirReqIgnoresMethodNotAllowed(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	s.NoteHTTP(http.StatusMethodNotAllowed, false)
	clk.t = clk.t.Add(24 * time.Hour)
	if got := s.StatsMap(); got != nil {
		t.Fatalf("405 不得计入: %v", got)
	}
}

func TestDirCacheConsensusNotesDirReq(t *testing.T) {
	s := NewDirCacheServer(t.TempDir(), nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus", http.NoBody))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("空缓存应得 404, got %d", rec.Code)
	}
	s.dirreq.mu.Lock()
	n := s.dirreq.notFound
	s.dirreq.mu.Unlock()
	if n != 1 {
		t.Fatalf("共识 404 应计入 dirreq not-found, got %d", n)
	}
	rec2 := httptest.NewRecorder()
	s.handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/tor/micro/all", http.NoBody))
	s.dirreq.mu.Lock()
	n2 := s.dirreq.notFound
	s.dirreq.mu.Unlock()
	if n2 != 1 {
		t.Fatalf("/tor/micro/all 不得计入 dirreq, not-found=%d", n2)
	}
	s.dirreq.mu.Lock()
	dOK, tOK := s.dirreq.directOK, s.dirreq.tunneledOK
	s.dirreq.mu.Unlock()
	if dOK != 0 || tOK != 0 {
		t.Fatalf("404 不得计入 complete, direct=%d tunneled=%d", dOK, tOK)
	}
}

func TestDirReq404OmitsDL(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	s.NoteHTTP(http.StatusNotFound, false)
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	if _, ok := got["dirreq-v3-direct-dl"]; ok {
		t.Fatalf("404 不得写 direct-dl: %v", got)
	}
	if _, ok := got["dirreq-v3-tunneled-dl"]; ok {
		t.Fatalf("404 不得写 tunneled-dl: %v", got)
	}
}

func TestDirReqDirectAndTunneledComplete(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	s.NoteHTTP(http.StatusOK, false)
	s.NoteHTTP(http.StatusOK, true)
	clk.t = clk.t.Add(24 * time.Hour)
	got := s.StatsMap()
	if got["dirreq-v3-direct-dl"] != "complete=1" {
		t.Fatalf("direct: %q", got["dirreq-v3-direct-dl"])
	}
	if got["dirreq-v3-tunneled-dl"] != "complete=1" {
		t.Fatalf("tunneled: %q", got["dirreq-v3-tunneled-dl"])
	}
	if strings.Contains(got["dirreq-v3-direct-dl"], "min=") || strings.Contains(got["dirreq-v3-tunneled-dl"], "d1=") {
		t.Fatalf("不得编造分位数: %v", got)
	}
}

func TestDirCacheBeginDirNotesTunneled(t *testing.T) {
	dir := t.TempDir()
	body := []byte("network-status-version 3 microdesc\n")
	if err := os.WriteFile(filepath.Join(dir, directory.ConsensusCacheFile(directory.FlavorMicrodesc)), body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDirCacheServer(dir, nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tor/status-vote/current/consensus-microdesc", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("DirPort 模拟应得 200, got %d", rec.Code)
	}
	conn, err := s.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("BEGIN_DIR 应得 200, got %d", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	s.dirreq.mu.Lock()
	dOK, tOK := s.dirreq.directOK, s.dirreq.tunneledOK
	s.dirreq.mu.Unlock()
	if dOK != 1 || tOK != 1 {
		t.Fatalf("DirPort complete=%d BEGIN_DIR complete=%d", dOK, tOK)
	}
}
