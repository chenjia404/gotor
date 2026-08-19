package crypto

import (
	"fmt"
	"sort"
)

// 子协议编号对照 tor-spec subprotocol-versioning 与 C Tor protover.h。
const (
	ProtoLink      uint8 = 0
	ProtoLinkAuth  uint8 = 1
	ProtoRelay     uint8 = 2
	ProtoDirCache  uint8 = 3
	ProtoHSDir     uint8 = 4
	ProtoHSIntro   uint8 = 5
	ProtoHSRend    uint8 = 6
	ProtoDesc      uint8 = 7
	ProtoMicrodesc uint8 = 8
	ProtoCons      uint8 = 9
	ProtoPadding   uint8 = 10
	ProtoFlowCtrl  uint8 = 11
	ProtoConflux   uint8 = 12
)

const (
	CapRelaySubproto uint8 = 5 // Relay=5 RELAY_NEGOTIATE_SUBPROTO
	CapRelayCGO      uint8 = 6 // Relay=6 RELAY_CRYPT_CGO
)

// SubprotoCap 是一条可协商的子协议能力。
type SubprotoCap struct {
	ProtocolID uint8
	Cap        uint8
}

func (c SubprotoCap) Encoding() []byte {
	return []byte{c.ProtocolID, c.Cap}
}

func (c SubprotoCap) String() string {
	return fmt.Sprintf("%s=%d", ProtocolName(c.ProtocolID), c.Cap)
}

// ProtocolName 返回 spec 里的协议名；未知 ID 用数字。
func ProtocolName(id uint8) string {
	names := [...]string{
		"Link", "LinkAuth", "Relay", "DirCache", "HSDir", "HSIntro",
		"HSRend", "Desc", "Microdesc", "Cons", "Padding", "FlowCtrl", "Conflux",
	}
	if int(id) < len(names) {
		return names[id]
	}
	return fmt.Sprintf("Proto%d", id)
}

// NegotiableSubprotoCaps 是现行 spec 允许放进 type 3 的能力表。
// 目前只有 RELAY_CRYPT_CGO（Relay=6 = [02 06]）。
var NegotiableSubprotoCaps = []SubprotoCap{
	{ProtocolID: ProtoRelay, Cap: CapRelayCGO},
}

func capAllowed(c SubprotoCap) bool {
	for _, a := range NegotiableSubprotoCaps {
		if a == c {
			return true
		}
	}
	return false
}

// ImplementedNegotiableCaps 是本客户端已经实现、可以请求启用的协商能力。
// CGO 已实现：对宣告 Relay=5 与 Relay=6 且 FlowCtrl=2 的 hop 请求 [02 06]。
func ImplementedNegotiableCaps() []SubprotoCap {
	return []SubprotoCap{{ProtocolID: ProtoRelay, Cap: CapRelayCGO}}
}

// EncodeSubprotoRequest 编码 type 3 的 DATA：若干 {protocol_id, cap}，按 ID 再 cap 升序。
func EncodeSubprotoRequest(caps []SubprotoCap) ([]byte, error) {
	if len(caps) == 0 {
		return nil, fmt.Errorf("subproto_request must list at least one capability")
	}
	sorted := append([]SubprotoCap(nil), caps...)
	sortSubprotoCaps(sorted)
	out := make([]byte, 0, 2*len(sorted))
	for i, c := range sorted {
		if !capAllowed(c) {
			return nil, fmt.Errorf("capability %s is not in the negotiable table", c)
		}
		if i > 0 && sorted[i-1] == c {
			return nil, fmt.Errorf("duplicate capability %s", c)
		}
		out = append(out, c.ProtocolID, c.Cap)
	}
	return out, nil
}

// ParseSubprotoRequest 解析 type 3 DATA。长度必须为偶数；重复或未登记能力报错。
func ParseSubprotoRequest(data []byte) ([]SubprotoCap, error) {
	if len(data) == 0 || len(data)%2 != 0 {
		return nil, fmt.Errorf("subproto_request length %d must be even and non-empty", len(data))
	}
	out := make([]SubprotoCap, 0, len(data)/2)
	seen := map[SubprotoCap]bool{}
	for i := 0; i < len(data); i += 2 {
		c := SubprotoCap{ProtocolID: data[i], Cap: data[i+1]}
		if !capAllowed(c) {
			return nil, fmt.Errorf("capability %s is not in the negotiable table", c)
		}
		if seen[c] {
			return nil, fmt.Errorf("duplicate capability %s", c)
		}
		seen[c] = true
		out = append(out, c)
	}
	return out, nil
}

func sortSubprotoCaps(caps []SubprotoCap) {
	sort.Slice(caps, func(i, j int) bool {
		if caps[i].ProtocolID != caps[j].ProtocolID {
			return caps[i].ProtocolID < caps[j].ProtocolID
		}
		return caps[i].Cap < caps[j].Cap
	})
}

// ProtoSupport 是对端宣告的子协议查询（共识 pr 行）。
type ProtoSupport interface {
	Supports(name string, ver int) bool
}

// SelectSubprotoRequest 选出可以放进 type 3 的能力。
// 必须同时满足：对端 Relay=5、对端宣告该能力、本端已实现、且在 spec 表内。
// 当前会请求 Relay=6，前提是对端 Relay=5、Relay=6 且 FlowCtrl=2。
func SelectSubprotoRequest(peer ProtoSupport) ([]SubprotoCap, error) {
	if peer == nil || !peer.Supports("Relay", int(CapRelaySubproto)) {
		return nil, nil
	}
	// CGO 的 v1 cell 不兼容流级 SENDME，必须同时有 FlowCtrl=2。
	if !peer.Supports("FlowCtrl", 2) {
		return nil, nil
	}
	var out []SubprotoCap
	for _, c := range ImplementedNegotiableCaps() {
		if !capAllowed(c) {
			return nil, fmt.Errorf("implemented capability %s is not negotiable", c)
		}
		if !peer.Supports(ProtocolName(c.ProtocolID), int(c.Cap)) {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, nil
	}
	sortSubprotoCaps(out)
	return out, nil
}

// EncodeNtorV3ClientMsg 组装客户端 CM：可选 CC_FIELD_REQUEST + subproto_request。
func EncodeNtorV3ClientMsg(requestCC bool, caps []SubprotoCap) ([]byte, error) {
	var exts []NtorV3Extension
	if requestCC {
		exts = append(exts, NtorV3Extension{Type: NtorV3ExtCCRequest})
	}
	if len(caps) > 0 {
		body, err := EncodeSubprotoRequest(caps)
		if err != nil {
			return nil, err
		}
		exts = append(exts, NtorV3Extension{Type: NtorV3ExtSubprotoRequest, Data: body})
	}
	return EncodeNtorV3Extensions(exts), nil
}
