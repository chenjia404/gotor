package directory

import (
	"fmt"
	"strconv"
	"strings"
)

// ExitPolicySummary 是共识 / microdescriptor 的 "p" 行摘要。
// 对照 dir-spec：`p` SP ("accept" / "reject") SP PortList
//
// accept 列表：仅列出的端口允许，其余拒绝。
// reject 列表：列出的端口拒绝，其余允许。
type ExitPolicySummary struct {
	acceptList bool
	ranges     []portRange
}

type portRange struct {
	lo, hi int
}

// ParseExitPolicySummary 解析完整 "p ..." 行或 "accept/reject ..." 主体。
func ParseExitPolicySummary(line string) (*ExitPolicySummary, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty exit policy summary")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid exit policy summary %q", line)
	}
	if fields[0] == "p" {
		fields = fields[1:]
	}
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid exit policy summary %q", line)
	}

	var acceptList bool
	switch fields[0] {
	case "accept":
		acceptList = true
	case "reject":
		acceptList = false
	default:
		return nil, fmt.Errorf("unknown exit policy verb %q", fields[0])
	}

	ranges, err := parsePortList(strings.Join(fields[1:], ""))
	if err != nil {
		return nil, err
	}
	return &ExitPolicySummary{acceptList: acceptList, ranges: ranges}, nil
}

func parsePortList(list string) ([]portRange, error) {
	if list == "" {
		return nil, fmt.Errorf("empty port list")
	}
	parts := strings.Split(list, ",")
	ranges := make([]portRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parsePortOrRange(part)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, portRange{lo: lo, hi: hi})
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("empty port list")
	}
	return ranges, nil
}

func parsePortOrRange(s string) (int, int, error) {
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err := parsePort(lo)
		if err != nil {
			return 0, 0, err
		}
		b, err := parsePort(hi)
		if err != nil {
			return 0, 0, err
		}
		if a > b {
			return 0, 0, fmt.Errorf("invalid port range %q", s)
		}
		return a, b, nil
	}
	p, err := parsePort(s)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

// Allows 按 dir-spec 摘要语义判断端口。
func (p *ExitPolicySummary) Allows(port int) bool {
	if p == nil || port < 1 || port > 65535 {
		return false
	}
	listed := false
	for _, r := range p.ranges {
		if port >= r.lo && port <= r.hi {
			listed = true
			break
		}
	}
	if p.acceptList {
		return listed
	}
	return !listed
}

// HasParsedPolicy 表示已从共识或 microdescriptor 读到 p 行。
func (r *Relay) HasParsedPolicy() bool {
	return r != nil && r.ExitPolicy != nil
}

// CanExitToPort 判断该 relay 是否适合作为指定端口的 exit。
// 有 p 行时以摘要为准；否则退回 Exit flag（共识-microdesc 在拉 microdesc 前的启发式）。
func (r *Relay) CanExitToPort(port int) bool {
	if r == nil {
		return false
	}
	if r.ExitPolicy != nil {
		return r.ExitPolicy.Allows(port)
	}
	return r.IsExit()
}
