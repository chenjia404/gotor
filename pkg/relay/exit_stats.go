package relay

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const exitStatsPeriod = 24 * time.Hour

// C Tor rephist.c 的 interesting ports；其余并入 other。
var exitInterestingPortList = []uint16{
	20, 21, 22, 23, 43, 53, 79, 80, 81, 88,
	110, 143, 194, 220, 389, 443, 464, 465, 531, 543,
	563, 587, 636, 706, 749, 873, 993, 995, 1194, 1293,
	1723, 1863, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389,
	3690, 4321, 4643, 5050, 5190, 5222, 5223, 6666, 6667, 6668,
	6669, 6697, 8000, 8008, 8080, 8082, 8087, 8088, 8443, 8880,
	9418, 9999, 19638,
}

var exitInterestingPorts map[uint16]struct{}

func init() {
	exitInterestingPorts = make(map[uint16]struct{}, len(exitInterestingPortList))
	for _, p := range exitInterestingPortList {
		exitInterestingPorts[p] = struct{}{}
	}
}

type exitPortCounters struct {
	written uint64
	read    uint64
	streams uint64
}

type exitCompleted struct {
	end   time.Time
	nsec  int
	ports map[uint16]exitPortCounters
	other exitPortCounters
}

// ExitStats 统计出口 TCP（非 BEGIN_DIR）的打开次数与读写字节。
// 满 24h 且该窗有观测才写入 extra-info；端口 KiB 向上取整，流数向上取 4。
type ExitStats struct {
	mu          sync.Mutex
	now         func() time.Time
	periodStart time.Time
	ports       map[uint16]*exitPortCounters
	other       exitPortCounters
	completed   *exitCompleted
}

func NewExitStats() *ExitStats {
	return newExitStats(func() time.Time { return time.Now().UTC() })
}

func newExitStats(now func() time.Time) *ExitStats {
	return &ExitStats{now: now, periodStart: now()}
}

// NoteOpened 在 RELAY_BEGIN 成功 CONNECTED 后计一次打开。port=0 忽略。
func (s *ExitStats) NoteOpened(port uint16) {
	if s == nil || port == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	s.bucketLocked(port).streams++
}

// NoteBytes written 为写入远端 TCP（客户端→互联网），read 为从远端读出。
func (s *ExitStats) NoteBytes(port uint16, written, read uint64) {
	if s == nil || port == 0 || (written == 0 && read == 0) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked(s.now())
	b := s.bucketLocked(port)
	b.written += written
	b.read += read
}

func (s *ExitStats) bucketLocked(port uint16) *exitPortCounters {
	if _, ok := exitInterestingPorts[port]; !ok {
		return &s.other
	}
	if s.ports == nil {
		s.ports = make(map[uint16]*exitPortCounters)
	}
	c := s.ports[port]
	if c == nil {
		c = &exitPortCounters{}
		s.ports[port] = c
	}
	return c
}

// StatsMap 返回已完成 24h 窗的 exit-stats-end / kibibytes / streams。无观测则空。
func (s *ExitStats) StatsMap() map[string]string {
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
	written := formatExitPorts(c, func(p exitPortCounters) uint64 { return roundUpKiB(p.written) })
	read := formatExitPorts(c, func(p exitPortCounters) uint64 { return roundUpKiB(p.read) })
	streams := formatExitPorts(c, func(p exitPortCounters) uint64 { return roundUp4(p.streams) })
	if written == "" && read == "" && streams == "" {
		return nil
	}
	out := map[string]string{
		"exit-stats-end": fmt.Sprintf("%s (%d s)",
			c.end.UTC().Format("2006-01-02 15:04:05"), c.nsec),
	}
	if written != "" {
		out["exit-kibibytes-written"] = written
	}
	if read != "" {
		out["exit-kibibytes-read"] = read
	}
	if streams != "" {
		out["exit-streams-opened"] = streams
	}
	return out
}

func (s *ExitStats) rotateLocked(now time.Time) {
	end := s.periodStart.Add(exitStatsPeriod)
	if now.Before(end) {
		return
	}
	if s.hasCountsLocked() {
		nsec := int(end.Sub(s.periodStart).Seconds())
		if nsec <= 0 {
			nsec = int(exitStatsPeriod.Seconds())
		}
		copied := make(map[uint16]exitPortCounters, len(s.ports))
		for p, c := range s.ports {
			if c != nil {
				copied[p] = *c
			}
		}
		s.completed = &exitCompleted{
			end:   end.UTC(),
			nsec:  nsec,
			ports: copied,
			other: s.other,
		}
	}
	unix := now.Unix()
	nsec := int64(exitStatsPeriod.Seconds())
	s.periodStart = time.Unix((unix/nsec)*nsec, 0).UTC()
	if !s.periodStart.After(end) {
		s.periodStart = end
	}
	s.ports = nil
	s.other = exitPortCounters{}
}

func (s *ExitStats) hasCountsLocked() bool {
	if s.other.written+s.other.read+s.other.streams > 0 {
		return true
	}
	for _, c := range s.ports {
		if c != nil && c.written+c.read+c.streams > 0 {
			return true
		}
	}
	return false
}

func formatExitPorts(c *exitCompleted, val func(exitPortCounters) uint64) string {
	if c == nil {
		return ""
	}
	parts := make([]string, 0, len(exitInterestingPortList)+1)
	for _, p := range exitInterestingPortList {
		n := val(c.ports[p])
		if n == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d=%d", p, n))
	}
	if n := val(c.other); n > 0 {
		parts = append(parts, fmt.Sprintf("other=%d", n))
	}
	return strings.Join(parts, ",")
}

func roundUpKiB(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return (n + 1023) / 1024
}
