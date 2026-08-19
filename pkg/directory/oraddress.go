package directory

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseORAddress 解析共识 / microdescriptor 的 OR 地址（dir-spec "a" 行）。
//
// 格式：ADDRESS ":" PORT。IPv6 必须带方括号，例如 "[2001:db8::1]:9001"。
func ParseORAddress(addrPort string) (net.IP, int, error) {
	addrPort = strings.TrimSpace(addrPort)
	if addrPort == "" {
		return nil, 0, fmt.Errorf("empty OR address")
	}
	host, portStr, err := net.SplitHostPort(addrPort)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid OR address %q: %w", addrPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid OR port %q", portStr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("OR address host is not an IP: %q", host)
	}
	if !usableORIP(ip) {
		return nil, 0, fmt.Errorf("unusable OR IP %s", ip)
	}
	return ip, port, nil
}

func usableORIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

// applyALine 处理共识或 microdescriptor 的 "a" 行。
func applyALine(r *Relay, line string) {
	if r == nil {
		return
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "a "))
	if rest == "" {
		return
	}
	if strings.HasPrefix(rest, "sha256=") {
		if r.MicrodescDigest == "" {
			r.MicrodescDigest = strings.TrimPrefix(rest, "sha256=")
		}
		return
	}
	// 只取第一个字段，忽略行尾注释。
	if fields := strings.Fields(rest); len(fields) > 0 {
		rest = fields[0]
	}
	ip, port, err := ParseORAddress(rest)
	if err != nil {
		return
	}
	r.applyORAddress(ip, port)
}

func (r *Relay) applyORAddress(ip net.IP, port int) {
	if r == nil || ip == nil {
		return
	}
	if ip.To4() != nil {
		// r 行已有主 IPv4；附加 IPv4 不用于 EXTEND2 [01]。
		return
	}
	if r.IPv6 != "" {
		return
	}
	r.IPv6 = ip.String()
	r.IPv6Port = port
}

// IPv6ORAddress 返回可用于 EXTEND2 [01] 的 IPv6 ORPort。
func (r *Relay) IPv6ORAddress() (net.IP, uint16, bool) {
	if r == nil || r.IPv6 == "" || r.IPv6Port < 1 || r.IPv6Port > 65535 {
		return nil, 0, false
	}
	ip := net.ParseIP(r.IPv6)
	if ip == nil || ip.To4() != nil || ip.To16() == nil || !usableORIP(ip) {
		return nil, 0, false
	}
	return ip, uint16(r.IPv6Port), true
}

// HasIPv6ORPort 表示共识已给出可用的 IPv6 OR 地址。
func (r *Relay) HasIPv6ORPort() bool {
	_, _, ok := r.IPv6ORAddress()
	return ok
}

// ShouldIncludeExtendIPv6 表示 EXTEND2 应附加 [01]。
//
// 必须有合法 IPv6 ORPort。若已解析 pr 行，还要求宣告 Relay=3（RELAY_EXTEND_IPv6）。
// 未解析到 pr 时，有 IPv6 地址即附加（与 UseNtorV3 对缺 pr 的处理一致：按现行 mainnet 默认）。
func (r *Relay) ShouldIncludeExtendIPv6() bool {
	if !r.HasIPv6ORPort() {
		return false
	}
	if len(r.Protocols) == 0 {
		return true
	}
	return r.AdvertisesExtendIPv6()
}
