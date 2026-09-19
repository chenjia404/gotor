package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	s.NoteHTTP(http.StatusOK)
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
	s.NoteHTTP(http.StatusOK)
	s.NoteHTTP(http.StatusNotFound)
	s.NoteHTTP(http.StatusNotModified)
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
}

func TestDirReqIgnoresMethodNotAllowed(t *testing.T) {
	clk := &dirreqClock{t: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}
	s := newDirReqStats(clk.Now)
	s.NoteHTTP(http.StatusMethodNotAllowed)
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
}
