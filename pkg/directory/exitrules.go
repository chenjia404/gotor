package directory

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ExitPolicy 是 server descriptor 的完整 accept/reject 列表。
//
// 对照 dir-spec server-descriptor-format：
//
//	exitpattern ::= addrspec ":" portspec
//	规则按顺序匹配；无匹配则接受。
//	连接端口 0 永远不允许。
type ExitPolicy struct {
	rules []exitRule
}

type exitRule struct {
	accept bool
	allV4  bool
	allV6  bool
	net    *net.IPNet
	lo, hi int
}

// ParseExitPolicyLines 解析一组 descriptor 行。
// 返回完整 IPv4/IPv6 规则，以及可选的 ipv6-policy 摘要。
func ParseExitPolicyLines(lines []string) (*ExitPolicy, *ExitPolicySummary, error) {
	var rules []exitRule
	var ipv6 *ExitPolicySummary
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "accept", "reject":
			rule, err := parseExitRule(fields)
			if err != nil {
				return nil, nil, err
			}
			rules = append(rules, rule)
		case "ipv6-policy":
			pol, err := ParseExitPolicySummary(line)
			if err != nil {
				return nil, nil, err
			}
			ipv6 = pol
		default:
			return nil, nil, fmt.Errorf("unknown exit policy line %q", line)
		}
	}
	if len(rules) == 0 && ipv6 == nil {
		return nil, nil, fmt.Errorf("no exit policy rules")
	}
	var pol *ExitPolicy
	if len(rules) > 0 {
		pol = &ExitPolicy{rules: rules}
	}
	return pol, ipv6, nil
}

func parseExitRule(fields []string) (exitRule, error) {
	if len(fields) < 2 {
		return exitRule{}, fmt.Errorf("invalid exit rule %q", strings.Join(fields, " "))
	}
	var accept bool
	switch fields[0] {
	case "accept":
		accept = true
	case "reject":
		accept = false
	default:
		return exitRule{}, fmt.Errorf("unknown exit rule verb %q", fields[0])
	}
	// extra arguments SHOULD be accepted and ignored
	pattern := fields[1]
	addr, lo, hi, err := parseExitPattern(pattern)
	if err != nil {
		return exitRule{}, err
	}
	rule := exitRule{accept: accept, lo: lo, hi: hi}
	switch {
	case addr == "*" || addr == "*4":
		rule.allV4 = true
	case addr == "*6":
		rule.allV6 = true
	default:
		n, err := parseAddrSpec(addr)
		if err != nil {
			return exitRule{}, err
		}
		rule.net = n
	}
	return rule, nil
}

// parseExitPattern 拆 addrspec:portspec。IPv6 必须带方括号。
func parseExitPattern(pattern string) (addr string, lo, hi int, err error) {
	if pattern == "" {
		return "", 0, 0, fmt.Errorf("empty exit pattern")
	}
	var portspec string
	if strings.HasPrefix(pattern, "[") {
		end := strings.IndexByte(pattern, ']')
		if end < 0 {
			return "", 0, 0, fmt.Errorf("unclosed IPv6 addrspec %q", pattern)
		}
		addr = pattern[:end+1]
		rest := pattern[end+1:]
		if strings.HasPrefix(rest, "/") {
			slashEnd := strings.IndexByte(rest, ':')
			if slashEnd < 0 {
				return "", 0, 0, fmt.Errorf("missing portspec in %q", pattern)
			}
			addr += rest[:slashEnd]
			rest = rest[slashEnd:]
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, 0, fmt.Errorf("missing portspec in %q", pattern)
		}
		portspec = rest[1:]
	} else {
		colon := strings.LastIndexByte(pattern, ':')
		if colon < 0 {
			return "", 0, 0, fmt.Errorf("missing portspec in %q", pattern)
		}
		addr = pattern[:colon]
		portspec = pattern[colon+1:]
	}
	lo, hi, err = parsePortSpec(portspec)
	if err != nil {
		return "", 0, 0, err
	}
	return addr, lo, hi, nil
}

func parsePortSpec(s string) (int, int, error) {
	if s == "*" {
		return 1, 65535, nil
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err := parsePolicyPort(lo)
		if err != nil {
			return 0, 0, err
		}
		b, err := parsePolicyPort(hi)
		if err != nil {
			return 0, 0, err
		}
		if a > b {
			return 0, 0, fmt.Errorf("invalid port range %q", s)
		}
		return a, b, nil
	}
	p, err := parsePolicyPort(s)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

// parsePolicyPort 允许 0（部分实现会写出）；连接端口 0 仍永远拒绝。
func parsePolicyPort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

func parseAddrSpec(addr string) (*net.IPNet, error) {
	if strings.HasPrefix(addr, "[") {
		return parseIPv6AddrSpec(addr)
	}
	return parseIPv4AddrSpec(addr)
}

func parseIPv6AddrSpec(addr string) (*net.IPNet, error) {
	end := strings.IndexByte(addr, ']')
	if end < 0 || !strings.HasPrefix(addr, "[") {
		return nil, fmt.Errorf("invalid IPv6 addrspec %q", addr)
	}
	ipStr := addr[1:end]
	bits := 128
	rest := addr[end+1:]
	if rest != "" {
		if !strings.HasPrefix(rest, "/") {
			return nil, fmt.Errorf("invalid IPv6 addrspec %q", addr)
		}
		n, err := strconv.Atoi(rest[1:])
		if err != nil || n < 0 || n > 128 {
			return nil, fmt.Errorf("invalid IPv6 prefix %q", rest)
		}
		bits = n
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address %q", ipStr)
	}
	mask := net.CIDRMask(bits, 128)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

func parseIPv4AddrSpec(addr string) (*net.IPNet, error) {
	host, maskPart, hasMask := strings.Cut(addr, "/")
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address %q", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("expected IPv4 addrspec, got %q", addr)
	}
	bits := 32
	if hasMask {
		if dotted := net.ParseIP(maskPart); dotted != nil {
			m4 := dotted.To4()
			if m4 == nil {
				return nil, fmt.Errorf("invalid IPv4 mask %q", maskPart)
			}
			mask := net.IPMask(m4)
			ones, _ := mask.Size()
			if ones < 0 {
				return nil, fmt.Errorf("invalid IPv4 mask %q", maskPart)
			}
			return &net.IPNet{IP: ip4.Mask(mask), Mask: mask}, nil
		}
		n, err := strconv.Atoi(maskPart)
		if err != nil || n < 0 || n > 32 {
			return nil, fmt.Errorf("invalid IPv4 prefix %q", maskPart)
		}
		bits = n
	}
	mask := net.CIDRMask(bits, 32)
	return &net.IPNet{IP: ip4.Mask(mask), Mask: mask}, nil
}

func (p *ExitPolicy) hasIPv6Rule() bool {
	if p == nil {
		return false
	}
	for i := range p.rules {
		r := &p.rules[i]
		if r.allV6 || (r.net != nil && r.net.IP.To4() == nil) {
			return true
		}
	}
	return false
}

func (r *exitRule) matchesFamily(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if r.allV4 {
			return true
		}
		return r.net != nil && r.net.IP.To4() != nil && r.net.Contains(v4)
	}
	if r.allV6 {
		return true
	}
	return r.net != nil && r.net.IP.To4() == nil && r.net.Contains(ip)
}

func (r *exitRule) matchesPort(port int) bool {
	return port >= r.lo && port <= r.hi
}

// Allows 按顺序匹配。无匹配则接受（dir-spec）。端口 0 永远拒绝。
func (p *ExitPolicy) Allows(ip net.IP, port int) bool {
	if p == nil || ip == nil || port < 1 || port > 65535 {
		return false
	}
	for i := range p.rules {
		r := &p.rules[i]
		if r.matchesFamily(ip) && r.matchesPort(port) {
			return r.accept
		}
	}
	return true
}

// AllowsUnknown 用于主机名 / 未知地址（对照 C Tor compare_unknown_tor_addr_to_addr_policy）。
// 通配 IPv4 规则立即决定；仅有地址相关规则时，存在 accept 则按「可能允许」放行。
// 无匹配则接受。
func (p *ExitPolicy) AllowsUnknown(port int) bool {
	if p == nil || port < 1 || port > 65535 {
		return false
	}
	maybeAccept := false
	maybeReject := false
	for i := range p.rules {
		r := &p.rules[i]
		if !r.matchesPort(port) {
			continue
		}
		if r.allV4 {
			return r.accept
		}
		if r.net != nil && r.net.IP.To4() != nil {
			if r.accept {
				maybeAccept = true
			} else {
				maybeReject = true
			}
		}
	}
	if maybeAccept {
		return true
	}
	if maybeReject {
		return false
	}
	return true
}
