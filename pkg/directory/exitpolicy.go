package directory

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ExitPolicySummary 是共识 / microdescriptor 的端口摘要。
//
// 对照 dir-spec：
//
//	p  SP ("accept" / "reject") SP PortList   — IPv4
//	p6 SP ("accept" / "reject") SP PortList   — IPv6
//
// accept 列表：仅列出的端口允许，其余拒绝。
// reject 列表：列出的端口拒绝，其余允许。
//
// 缺 p6 等价于 `p6 reject 1-65535`，不得用 IPv4 摘要或 Exit flag 放行 IPv6。
type ExitPolicySummary struct {
	acceptList bool
	ranges     []portRange
}

type portRange struct {
	lo, hi int
}

// ParseExitPolicySummary 解析 "p ..." / "p6 ..." / "ipv6-policy ..." 或 "accept/reject ..." 主体。
func ParseExitPolicySummary(line string) (*ExitPolicySummary, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty exit policy summary")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid exit policy summary %q", line)
	}
	switch fields[0] {
	case "p", "p6", "ipv6-policy":
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

// HasParsedPolicy 表示已读到 IPv4 摘要、IPv6 摘要或完整 accept/reject 列表。
func (r *Relay) HasParsedPolicy() bool {
	return r != nil && (r.ExitPolicy != nil || r.ExitPolicyIPv6 != nil || r.ExitRules != nil)
}

// HasParsedIPv6Policy 表示已读到 p6 / ipv6-policy。缺行按 spec 视为拒绝全部 IPv6。
func (r *Relay) HasParsedIPv6Policy() bool {
	return r != nil && r.ExitPolicyIPv6 != nil
}

// CanExitToPort 判断该 relay 是否适合作为指定端口的 IPv4 / 主机名出口。
// 有完整规则时按未知地址语义；有 p 行时以 IPv4 摘要为准；否则退回 Exit flag。
func (r *Relay) CanExitToPort(port int) bool {
	if r == nil {
		return false
	}
	if r.ExitRules != nil {
		return r.ExitRules.AllowsUnknown(port)
	}
	if r.ExitPolicy != nil {
		return r.ExitPolicy.Allows(port)
	}
	return r.IsExit()
}

// CanExitTo 按目的地址族选择策略。
// IPv6：p6 / ipv6-policy / 完整 IPv6 规则；缺 p6 且无 IPv6 规则则拒绝。
// IPv4：完整规则或 p 行。ip==nil 时与 CanExitToPort 相同（主机名 / 预建）。
func (r *Relay) CanExitTo(ip net.IP, port int) bool {
	if r == nil {
		return false
	}
	if ip == nil {
		return r.CanExitToPort(port)
	}
	if port < 1 || port > 65535 {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if r.ExitRules != nil {
			return r.ExitRules.Allows(v4, port)
		}
		if r.ExitPolicy != nil {
			return r.ExitPolicy.Allows(port)
		}
		return r.IsExit()
	}
	if ip.To16() == nil {
		return false
	}
	if r.ExitRules != nil && r.ExitRules.hasIPv6Rule() {
		return r.ExitRules.Allows(ip, port)
	}
	if r.ExitPolicyIPv6 != nil {
		return r.ExitPolicyIPv6.Allows(port)
	}
	return false
}

// AllowsExit 供电路 ExitFilter 使用。
func (r *Relay) AllowsExit(ip net.IP, port int) bool {
	return r.CanExitTo(ip, port)
}

// AllowsExitTarget 按选路目标（端口 + 可选字面量 IP）判断。
func (r *Relay) AllowsExitTarget(port int, ip net.IP) bool {
	return r.CanExitTo(ip, port)
}
