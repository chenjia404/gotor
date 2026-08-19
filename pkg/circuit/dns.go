package circuit

// 远程主机名查询（RELAY_RESOLVE / RELAY_RESOLVED）。
//
// 对照：
//   - https://spec.torproject.org/tor-spec/remote-hostname-lookup.html
//   - https://spec.torproject.org/tor-spec/relay-cells.html
//   - C Tor：src/core/or/relay.c（stream_id==0 的 RELAY_RESOLVE 直接丢弃，bug 7889）
//   - C Tor：src/core/or/connection_edge.c（RESOLVED 多条 answer；0xF0/0xF1 的 Value 是字符串）

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// RELAY_RESOLVED 记录类型（tor-spec remote-hostname-lookup）。
const (
	DNSTypeHostname = 0x00 // 主机名（PTR 应答）
	DNSTypeIPv4     = 0x04 // IPv4
	DNSTypeIPv6     = 0x06 // IPv6
	DNSTypeError    = 0xF0 // 瞬时错误
	DNSTypeErrorTTL = 0xF1 // 非瞬时错误
)

// DNS 传统 RCODE，仅作文档对照。RELAY_RESOLVED 的 0xF0/0xF1 Value
// 在 C Tor 里是字符串（如 "Error resolving hostname"），不是 1 字节错误码。
const (
	DNSErrorNone                = 0x00
	DNSErrorFormat              = 0x01
	DNSErrorServerFailure       = 0x02
	DNSErrorNotExist            = 0x03
	DNSErrorNotImplemented      = 0x04
	DNSErrorRefused             = 0x05
	DNSErrorTransientFailure    = 0xF0
	DNSErrorNonTransientFailure = 0xF1
)

const dnsResolveTimeout = 30 * time.Second

var hexNibble = []byte("0123456789abcdef")

// DNSResult 是一条 RELAY_RESOLVED 的全部有效应答。
type DNSResult struct {
	Type         byte     // 优先 IPv4，否则 IPv6，否则主机名，否则错误类型
	TTL          uint32   // 首条对应类型应答的 TTL
	Addresses    []net.IP // 全部 IPv4（在前）+ IPv6
	Hostname     string   // PTR 主机名
	Error        byte     // 仅无有效应答时：0xF0 或 0xF1
	ErrorMessage string   // 0xF0/0xF1 的 Value 字符串（可空）
}

// ResolveHostname 经电路把主机名解析成 IP。不得走本机 DNS。
func (c *Circuit) ResolveHostname(ctx context.Context, hostname string) (*DNSResult, error) {
	name, err := normalizeResolveName(hostname)
	if err != nil {
		return nil, err
	}
	return c.sendResolve(ctx, name)
}

// ResolveIP 经电路做反向查询。载荷与正向相同：NUL 结尾的
// in-addr.arpa / ip6.arpa 主机名，不是 TYPE|LENGTH|ADDRESS 二进制。
func (c *Circuit) ResolveIP(ctx context.Context, ipAddr net.IP) (*DNSResult, error) {
	name, err := PTRHostname(ipAddr)
	if err != nil {
		return nil, err
	}
	return c.sendResolve(ctx, name)
}

func (c *Circuit) sendResolve(ctx context.Context, name string) (*DNSResult, error) {
	streamID, err := c.AllocateStreamID()
	if err != nil {
		return nil, fmt.Errorf("allocate stream ID for RELAY_RESOLVE: %w", err)
	}
	defer c.ReleaseStreamID(streamID)

	payload := buildResolvePayload(name)
	resolveCell, err := cell.NewRelayCell(streamID, cell.RelayResolve, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create RELAY_RESOLVE cell: %w", err)
	}
	if err := c.SendRelayCell(resolveCell); err != nil {
		return nil, fmt.Errorf("failed to send RELAY_RESOLVE: %w", err)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, dnsResolveTimeout)
	defer cancel()

	resolvedCell, err := c.waitResolved(resolveCtx, streamID)
	if err != nil {
		return nil, err
	}

	result, err := parseResolvedCell(resolvedCell.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RELAY_RESOLVED: %w", err)
	}
	if len(result.Addresses) == 0 && result.Hostname == "" {
		if result.Type == DNSTypeError || result.Type == DNSTypeErrorTTL {
			return result, fmt.Errorf("DNS resolution failed: type=0x%02X %s", result.Type, result.ErrorMessage)
		}
		return result, fmt.Errorf("DNS resolution returned no answers")
	}
	return result, nil
}

// waitResolved 等到本 StreamID 的 RELAY_RESOLVED 或 RELAY_END。
// 其它 cell 交给 stream manager，避免与并发 BEGIN/DATA 互相饿死。
func (c *Circuit) waitResolved(ctx context.Context, streamID uint16) (*cell.RelayCell, error) {
	for {
		relayCell, err := c.ReceiveRelayCell(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to receive RELAY_RESOLVED: %w", err)
		}
		if relayCell.StreamID != streamID {
			_ = c.deliverToStream(relayCell)
			continue
		}
		switch relayCell.Command {
		case cell.RelayResolved:
			return relayCell, nil
		case cell.RelayEnd:
			reason := "unknown"
			if len(relayCell.Data) > 0 {
				reason = fmt.Sprintf("reason=%d", relayCell.Data[0])
			}
			return nil, fmt.Errorf("RELAY_END during resolve: %s", reason)
		default:
			continue
		}
	}
}

func normalizeResolveName(hostname string) (string, error) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", fmt.Errorf("hostname cannot be empty")
	}
	if strings.IndexByte(hostname, 0) >= 0 {
		return "", fmt.Errorf("hostname contains NUL")
	}
	if strings.HasSuffix(strings.ToLower(hostname), ".onion") {
		return "", fmt.Errorf("onion addresses must not be resolved via RELAY_RESOLVE")
	}
	return hostname, nil
}

// buildResolvePayload 按 spec 编 NUL 结尾主机名。
func buildResolvePayload(name string) []byte {
	return append([]byte(name), 0x00)
}

// PTRHostname 把 IP 编成反查名。正向/反向 RELAY_RESOLVE 用同一载荷格式。
func PTRHostname(ipAddr net.IP) (string, error) {
	if ipAddr == nil {
		return "", fmt.Errorf("IP address cannot be nil")
	}
	if v4 := ipAddr.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v6 := ipAddr.To16()
	if v6 == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	var b strings.Builder
	b.Grow(72)
	for i := 15; i >= 0; i-- {
		b.WriteByte(hexNibble[v6[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hexNibble[v6[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String(), nil
}

// parseResolvedCell 解析 RELAY_RESOLVED：多条 TYPE|LENGTH|VALUE|TTL。
// 0xF0/0xF1 的 Value 是错误说明字符串，不是 1 字节 RCODE。
func parseResolvedCell(data []byte) (*DNSResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty RELAY_RESOLVED data")
	}

	result := &DNSResult{
		Addresses: make([]net.IP, 0),
	}

	var (
		v4      []net.IP
		v6      []net.IP
		v4TTL   uint32
		v6TTL   uint32
		hostTTL uint32
		sawErr  byte
		errTTL  uint32
		errMsg  string
	)

	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		recordType := data[offset]
		length := int(data[offset+1])
		offset += 2
		if offset+length+4 > len(data) {
			return nil, fmt.Errorf("invalid RELAY_RESOLVED record: incomplete data")
		}
		value := data[offset : offset+length]
		offset += length
		ttl := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		switch recordType {
		case DNSTypeHostname:
			hostname := strings.TrimRight(string(value), "\x00")
			if hostname == "" {
				continue
			}
			if result.Hostname == "" {
				result.Hostname = hostname
				hostTTL = ttl
			}
		case DNSTypeIPv4:
			if length != 4 {
				return nil, fmt.Errorf("invalid IPv4 address length: %d", length)
			}
			if len(v4) == 0 {
				v4TTL = ttl
			}
			v4 = append(v4, net.IPv4(value[0], value[1], value[2], value[3]))
		case DNSTypeIPv6:
			if length != 16 {
				return nil, fmt.Errorf("invalid IPv6 address length: %d", length)
			}
			ip := make(net.IP, 16)
			copy(ip, value)
			if len(v6) == 0 {
				v6TTL = ttl
			}
			v6 = append(v6, ip)
		case DNSTypeError, DNSTypeErrorTTL:
			if sawErr == 0 {
				sawErr = recordType
				errTTL = ttl
				errMsg = strings.TrimRight(string(value), "\x00")
			}
		default:
			continue
		}
	}

	result.Addresses = append(result.Addresses, v4...)
	result.Addresses = append(result.Addresses, v6...)

	switch {
	case len(v4) > 0:
		result.Type = DNSTypeIPv4
		result.TTL = v4TTL
	case len(v6) > 0:
		result.Type = DNSTypeIPv6
		result.TTL = v6TTL
	case result.Hostname != "":
		result.Type = DNSTypeHostname
		result.TTL = hostTTL
	case sawErr != 0:
		result.Type = sawErr
		result.Error = sawErr
		result.ErrorMessage = errMsg
		result.TTL = errTTL
	default:
		return nil, fmt.Errorf("no valid DNS records found in RELAY_RESOLVED")
	}
	return result, nil
}
