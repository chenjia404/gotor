package directory

import (
	"strconv"
	"strings"
)

// ProtoVersions 是共识 pr 行解析出的子协议版本。
// 例：Relay=1-4 FlowCtrl=1-2 LinkAuth=1,3
type ProtoVersions map[string][]protoRange

type protoRange struct {
	lo int
	hi int
}

// ParseProtoLine 解析 "pr Relay=4 FlowCtrl=1-2 ..." 或去掉前缀后的字段列表。
func ParseProtoLine(line string) ProtoVersions {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "pr ")
	out := make(ProtoVersions)
	for _, field := range strings.Fields(line) {
		name, vers, ok := strings.Cut(field, "=")
		if !ok || name == "" || vers == "" {
			continue
		}
		ranges := parseProtoVersionList(vers)
		if len(ranges) == 0 {
			continue
		}
		out[name] = ranges
	}
	return out
}

func parseProtoVersionList(s string) []protoRange {
	var out []protoRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loStr, hiStr, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(loStr)
		if err != nil || lo < 0 {
			continue
		}
		hi := lo
		if isRange {
			hi, err = strconv.Atoi(hiStr)
			if err != nil || hi < lo {
				continue
			}
		}
		out = append(out, protoRange{lo: lo, hi: hi})
	}
	return out
}

// Supports 表示该协议是否包含给定版本号。
func (p ProtoVersions) Supports(name string, ver int) bool {
	if p == nil {
		return false
	}
	for _, r := range p[name] {
		if ver >= r.lo && ver <= r.hi {
			return true
		}
	}
	return false
}

// HasNtorV3Keys 表示 ntor-v3 所需的 Ed25519 主身份 + ntor onion key 已齐。
func (r *Relay) HasNtorV3Keys() bool {
	return r != nil && r.HasNtorKeys() && len(r.IdentityKey) == 32 && !allZero(r.IdentityKey)
}

// UseNtorV3 按最新 spec：有 Relay=4 且具备 Ed25519 主身份时使用 ntor-v3。
// 未解析到 pr 行时，只要密钥齐全也走 ntor-v3（当前 mainnet 默认）。
func (r *Relay) UseNtorV3() bool {
	if !r.HasNtorV3Keys() {
		return false
	}
	if len(r.Protocols) == 0 {
		return true
	}
	return r.Protocols.Supports("Relay", 4)
}

// RequestCongestionControl 仅在明确宣告 FlowCtrl=2 时请求 prop324。
func (r *Relay) RequestCongestionControl() bool {
	if r == nil {
		return false
	}
	return r.Protocols.Supports("FlowCtrl", 2)
}

// SupportsSubprotoRequest 表示对端宣告 Relay=5（RELAY_NEGOTIATE_SUBPROTO）。
func (r *Relay) SupportsSubprotoRequest() bool {
	if r == nil {
		return false
	}
	return r.Protocols.Supports("Relay", 5)
}

// Supports 把 Relay 当作 crypto.ProtoSupport，供 SelectSubprotoRequest 使用。
func (r *Relay) Supports(name string, ver int) bool {
	if r == nil {
		return false
	}
	return r.Protocols.Supports(name, ver)
}

// AdvertisesExtendIPv6 表示对端宣告 Relay=3（RELAY_EXTEND_IPv6）。
// proposal 346：子协议号是独立 flag；Relay=4 并不蕴含 Relay=3。
func (r *Relay) AdvertisesExtendIPv6() bool {
	if r == nil {
		return false
	}
	return r.Protocols.Supports("Relay", 3)
}

// AdvertisesConflux 表示该中继宣告了可链接电路的 Conflux 能力。
//
// proposal 346：子协议号是独立 flag，Conflux=2 并不蕴含 Conflux=1。
// mainnet 常见只写 `Conflux=2`（见共识 pr 行），这两种都表示支持 LINK/LINKED/SWITCH。
func (r *Relay) AdvertisesConflux() bool {
	if r == nil {
		return false
	}
	return r.Protocols.Supports("Conflux", 1) || r.Protocols.Supports("Conflux", 2)
}
