package relay

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const dirreqPeriod = 24 * time.Hour

type dirreqCompleted struct {
	end         time.Time
	nsec        int
	served      uint64
	ok          uint64
	notEnough   uint64
	unavailable uint64
	notFound    uint64
	notModified uint64
	busy        uint64
	directOK    uint64
	tunneledOK  uint64
	uniqueIPs   uint64
	reqs        uint64
}

// DirReqStats 统计 v3 网络状态请求的 HTTP 应答（dirreq-v3-resp）、
// DirPort / BEGIN_DIR 完成次数（dirreq-v3-*-dl 的 complete），
// 以及无法映射国家时的 ips/reqs（仅 ??）。
// 满 24h 且该窗有计数才写入 extra-info；无 geoip，不写国家码；不写下载分位数。
type DirReqStats struct {
	mu          sync.Mutex
	now         func() time.Time
	periodStart time.Time
	served      uint64
	ok          uint64
	notEnough   uint64
	unavailable uint64
	notFound    uint64
	notModified uint64
	busy        uint64
	directOK    uint64
	tunneledOK  uint64
	reqs        uint64
	ips         map[string]struct{}
	completed   *dirreqCompleted
}

func NewDirReqStats() *DirReqStats {
	return newDirReqStats(func() time.Time { return time.Now().UTC() })
}

func newDirReqStats(now func() time.Time) *DirReqStats {
	t := now()
	return &DirReqStats{now: now, periodStart: t}
}

type dirreqTunneledKey struct{}
type dirreqRemoteKey struct{}

func withDirreqTunneled(r *http.Request) *http.Request {
	if r == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), dirreqTunneledKey{}, true))
}

func withDirreqRemote(r *http.Request, remote string) *http.Request {
	if r == nil || remote == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), dirreqRemoteKey{}, remote))
}

func isDirreqTunneled(r *http.Request) bool {
	if r == nil {
		return false
	}
	v, _ := r.Context().Value(dirreqTunneledKey{}).(bool)
	return v
}

func dirreqRemote(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v, ok := r.Context().Value(dirreqRemoteKey{}).(string); ok && v != "" {
		return v
	}
	return r.RemoteAddr
}

// NoteHTTP 按应答状态计入当前 24h 窗。tunneled 为 BEGIN_DIR；非 v3 目录应答码忽略。
// remote 为 DirPort 对端或 BEGIN_DIR 相邻 OR；无 geoip 一律记入 ??。
func (s *DirReqStats) NoteHTTP(status int, tunneled bool, remote string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	switch status {
	case http.StatusOK, 0:
		s.served++
		s.ok++
		if tunneled {
			s.tunneledOK++
		} else {
			s.directOK++
		}
	case http.StatusNotModified:
		s.notModified++
	case http.StatusNotFound:
		s.notFound++
	case http.StatusServiceUnavailable:
		s.unavailable++
	default:
		return
	}
	s.reqs++
	s.noteIPLocked(remote)
}

func (s *DirReqStats) noteIPLocked(remote string) {
	key := dirreqIPKey(remote)
	if key == "" {
		return
	}
	if s.ips == nil {
		s.ips = make(map[string]struct{})
	}
	s.ips[key] = struct{}{}
}

func dirreqIPKey(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// StatsMap 返回已完成窗的 dirreq-stats-end、ips/reqs（仅 ??）、resp 以及有 complete 时的 *-dl。无观测则空。
func (s *DirReqStats) StatsMap() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	if s.completed == nil {
		return nil
	}
	c := s.completed
	resp := formatDirReqResp(c)
	if resp == "" {
		return nil
	}
	out := map[string]string{
		"dirreq-stats-end": fmt.Sprintf("%s (%d s)",
			c.end.UTC().Format("2006-01-02 15:04:05"), c.nsec),
		"dirreq-v3-resp": resp,
	}
	if c.uniqueIPs > 0 {
		out["dirreq-v3-ips"] = fmt.Sprintf("??=%d", roundUp8(c.uniqueIPs))
	}
	if c.reqs > 0 {
		out["dirreq-v3-reqs"] = fmt.Sprintf("??=%d", roundUp8(c.reqs))
	}
	if c.directOK > 0 {
		out["dirreq-v3-direct-dl"] = fmt.Sprintf("complete=%d", c.directOK)
	}
	if c.tunneledOK > 0 {
		out["dirreq-v3-tunneled-dl"] = fmt.Sprintf("complete=%d", c.tunneledOK)
	}
	return out
}

func (s *DirReqStats) rotateLocked(now time.Time) {
	end := s.periodStart.Add(dirreqPeriod)
	if now.Before(end) {
		return
	}
	if s.hasCountsLocked() {
		nsec := int(end.Sub(s.periodStart).Seconds())
		if nsec <= 0 {
			nsec = int(dirreqPeriod.Seconds())
		}
		s.completed = &dirreqCompleted{
			end:         end.UTC(),
			nsec:        nsec,
			served:      s.served,
			ok:          s.ok,
			notEnough:   s.notEnough,
			unavailable: s.unavailable,
			notFound:    s.notFound,
			notModified: s.notModified,
			busy:        s.busy,
			directOK:    s.directOK,
			tunneledOK:  s.tunneledOK,
			uniqueIPs:   uint64(len(s.ips)),
			reqs:        s.reqs,
		}
	}
	// 空档不补零；当前窗对齐到 now。
	unix := now.Unix()
	nsec := int64(dirreqPeriod.Seconds())
	s.periodStart = time.Unix((unix/nsec)*nsec, 0).UTC()
	if !s.periodStart.After(end) {
		s.periodStart = end
	}
	s.served, s.ok, s.notEnough, s.unavailable = 0, 0, 0, 0
	s.notFound, s.notModified, s.busy = 0, 0, 0
	s.directOK, s.tunneledOK = 0, 0
	s.reqs = 0
	s.ips = nil
}

func (s *DirReqStats) hasCountsLocked() bool {
	return s.served+s.ok+s.notEnough+s.unavailable+s.notFound+s.notModified+s.busy+s.reqs > 0
}

func roundUp8(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return ((n + 7) / 8) * 8
}

func formatDirReqResp(c *dirreqCompleted) string {
	if c == nil {
		return ""
	}
	type kv struct {
		k string
		n uint64
	}
	order := []kv{
		{"served", c.served},
		{"ok", c.ok},
		{"not-enough-sigs", c.notEnough},
		{"unavailable", c.unavailable},
		{"not-found", c.notFound},
		{"not-modified", c.notModified},
		{"busy", c.busy},
	}
	parts := make([]string, 0, len(order))
	for _, p := range order {
		if p.n == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", p.k, roundUp4(p.n)))
	}
	return strings.Join(parts, ",")
}

func roundUp4(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return ((n + 3) / 4) * 4
}

func isV3NetworkStatusPath(path string) bool {
	path = strings.TrimSuffix(path, ".z")
	return strings.Contains(path, "/tor/status-vote/current/consensus")
}

type dirreqCapture struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (c *dirreqCapture) WriteHeader(code int) {
	if !c.wrote {
		c.status = code
		c.wrote = true
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *dirreqCapture) Write(p []byte) (int, error) {
	if !c.wrote {
		c.status = http.StatusOK
		c.wrote = true
	}
	return c.ResponseWriter.Write(p)
}

func (c *dirreqCapture) code() int {
	if c.status != 0 {
		return c.status
	}
	return http.StatusOK
}
