package relay

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/circuit"
)

const (
	exitResolveTTL = 60
	exitMaxDNSName = 253
)

// HandleResolve 在出口做 DNS，应答 RELAY_RESOLVED（remote-hostname-lookup）。
// StreamID==0 直接丢弃（C Tor bug 7889）。.onion 不解析。
func (m *ExitStreamManager) HandleResolve(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16, data []byte) error {
	if streamID == 0 {
		return nil
	}
	if m.policy == nil || !m.policy.AllowExit {
		return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
	}
	name := parseResolveName(data)
	if name == "" || len(name) > exitMaxDNSName {
		return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
	}
	if isOnionHost(name) {
		return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
	}

	rctx := ctx
	if circ != nil && circ.ctx != nil {
		rctx = circ.ctx
	}

	if isPTRName(name) {
		ip := parseARPAName(name)
		if ip == nil {
			return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
		}
		if dangerousExitIP(ip) {
			return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
		}
		names, err := m.lookupPTR(rctx, ip.String())
		if err != nil || len(names) == 0 {
			return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
		}
		return m.sendResolved(circ, clientConn, streamID, encodeResolvedHostname(names[0], exitResolveTTL))
	}

	ips, err := m.lookupIP(rctx, name)
	if err != nil || len(ips) == 0 {
		return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
	}
	allowV6 := m.policy != nil && m.policy.ipv6OK
	filtered := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() == nil && !allowV6 {
			continue
		}
		// RESOLVE 不带端口：只滤掉私网/特殊用途地址，端口策略在 BEGIN 执行
		if dangerousExitIP(ip) {
			continue
		}
		filtered = append(filtered, ip)
	}
	if len(filtered) == 0 {
		return m.sendResolved(circ, clientConn, streamID, encodeResolvedError(false, "Error resolving hostname"))
	}
	return m.sendResolved(circ, clientConn, streamID, encodeResolvedAddresses(filtered, exitResolveTTL))
}

func (m *ExitStreamManager) lookupPTR(ctx context.Context, arpa string) ([]string, error) {
	if m.lookupP != nil {
		return m.lookupP(ctx, arpa)
	}
	r := &net.Resolver{PreferGo: true}
	return r.LookupAddr(ctx, arpa)
}

func (m *ExitStreamManager) sendResolved(circ *ServerCircuit, clientConn net.Conn, streamID uint16, payload []byte) error {
	return m.sendRelay(circ, clientConn, streamID, cell.RelayResolved, payload)
}

func parseResolveName(data []byte) string {
	s := string(data)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func isPTRName(name string) bool {
	n := strings.ToLower(strings.Trim(name, "."))
	return strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa")
}

// parseARPAName 把 in-addr.arpa / ip6.arpa 转成 IP。Go LookupAddr 要的是 IP，不是 arpa 主机名。
func parseARPAName(name string) net.IP {
	n := strings.ToLower(strings.Trim(name, "."))
	if strings.HasSuffix(n, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(n, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return nil
		}
		host := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			return nil
		}
		return ip
	}
	if strings.HasSuffix(n, ".ip6.arpa") {
		parts := strings.Split(strings.TrimSuffix(n, ".ip6.arpa"), ".")
		if len(parts) != 32 {
			return nil
		}
		var raw [16]byte
		for i := 0; i < 16; i++ {
			hi, ok1 := unhexNibble(parts[31-2*i])
			lo, ok2 := unhexNibble(parts[30-2*i])
			if !ok1 || !ok2 {
				return nil
			}
			raw[i] = hi<<4 | lo
		}
		return net.IP(raw[:])
	}
	return nil
}

func unhexNibble(s string) (byte, bool) {
	if len(s) != 1 {
		return 0, false
	}
	c := s[0]
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func encodeResolvedAddresses(ips []net.IP, ttl uint32) []byte {
	var buf []byte
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			rec := make([]byte, 2+4+4)
			rec[0] = circuit.DNSTypeIPv4
			rec[1] = 4
			copy(rec[2:6], v4)
			binary.BigEndian.PutUint32(rec[6:], ttl)
			buf = append(buf, rec...)
			continue
		}
		v6 := ip.To16()
		if v6 == nil {
			continue
		}
		rec := make([]byte, 2+16+4)
		rec[0] = circuit.DNSTypeIPv6
		rec[1] = 16
		copy(rec[2:18], v6)
		binary.BigEndian.PutUint32(rec[18:], ttl)
		buf = append(buf, rec...)
	}
	if len(buf) == 0 {
		return encodeResolvedError(false, "Error resolving hostname")
	}
	return buf
}

func encodeResolvedHostname(host string, ttl uint32) []byte {
	host = strings.TrimRight(host, ".")
	if len(host) > 255 {
		host = host[:255]
	}
	n := len(host)
	rec := make([]byte, 2+n+4)
	rec[0] = circuit.DNSTypeHostname
	rec[1] = byte(n) // #nosec G115 -- 已截断 ≤255
	copy(rec[2:], host)
	binary.BigEndian.PutUint32(rec[2+len(host):], ttl)
	return rec
}

func encodeResolvedError(transient bool, msg string) []byte {
	if msg == "" {
		msg = "Error resolving hostname"
	}
	if len(msg) > 255 {
		msg = msg[:255]
	}
	typ := byte(circuit.DNSTypeErrorTTL)
	if transient {
		typ = circuit.DNSTypeError
	}
	n := len(msg)
	rec := make([]byte, 2+n+4)
	rec[0] = typ
	rec[1] = byte(n) // #nosec G115 -- 已截断 ≤255
	copy(rec[2:], msg)
	binary.BigEndian.PutUint32(rec[2+len(msg):], 0)
	return rec
}
