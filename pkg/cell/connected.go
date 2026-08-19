// Package cell — RELAY_CONNECTED 载荷编解码（tor-spec opening-streams）。
//
// 对照 C Tor connected_cell_parse / connected_cell_format_payload
// 与 testdata/ctor-official/cell_connected_vectors.json。
package cell

import (
	"encoding/binary"
	"fmt"
	"net"
)

const maxConnectedTTL = 7 * 24 * 3600 // C Tor：过大 TTL 视为 -1

// ConnectedInfo 解析后的 CONNECTED 载荷。
type ConnectedInfo struct {
	Addr net.IP
	TTL  int // 秒；未知/过大为 -1
}

// ParseConnectedPayload 解析 RELAY_CONNECTED 数据。
func ParseConnectedPayload(data []byte) (*ConnectedInfo, error) {
	info := &ConnectedInfo{TTL: -1}
	if len(data) == 0 {
		return info, nil
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("CONNECTED payload too short: %d", len(data))
	}

	// IPv6：4 零字节 + family(6) + 16 addr + 4 ttl
	if len(data) >= 5 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		family := data[4]
		if family != 6 {
			return nil, fmt.Errorf("unsupported CONNECTED family %d", family)
		}
		if len(data) < 5+16+4 {
			return nil, fmt.Errorf("truncated IPv6 CONNECTED")
		}
		info.Addr = net.IP(append([]byte(nil), data[5:21]...))
		ttl := int(binary.BigEndian.Uint32(data[21:25]))
		if ttl <= maxConnectedTTL {
			info.TTL = ttl
		}
		return info, nil
	}

	// IPv4：4 字节地址 [+ 可选 4 字节 TTL]
	info.Addr = net.IP(append([]byte(nil), data[0:4]...))
	if len(data) >= 8 {
		ttl := int(binary.BigEndian.Uint32(data[4:8]))
		if ttl <= maxConnectedTTL {
			info.TTL = ttl
		}
	}
	return info, nil
}

// FormatConnectedPayload 编码 CONNECTED 载荷（含 TTL）。
func FormatConnectedPayload(addr net.IP, ttl uint32) ([]byte, error) {
	if addr == nil {
		return nil, fmt.Errorf("nil address")
	}
	if v4 := addr.To4(); v4 != nil {
		out := make([]byte, 8)
		copy(out, v4)
		binary.BigEndian.PutUint32(out[4:], ttl)
		return out, nil
	}
	v6 := addr.To16()
	if v6 == nil {
		return nil, fmt.Errorf("invalid IP")
	}
	out := make([]byte, 25)
	// 4 零 + family 6 + addr + ttl
	out[4] = 6
	copy(out[5:21], v6)
	binary.BigEndian.PutUint32(out[21:], ttl)
	return out, nil
}
