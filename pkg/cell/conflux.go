package cell

import (
	"encoding/binary"
	"fmt"
)

// proposal 329 / C Tor conflux_cell.c + Arti tor-cell conflux.rs。
// 整数一律大端（tor-spec 默认网络序）。
const (
	ConfluxLinkVersion = 0x01
	ConfluxNonceLen    = 32
	// ConfluxLinkPayloadLen = VERSION(1) + NONCE(32) + LAST_SEQNO_SENT(8) + LAST_SEQNO_RECV(8) + DESIRED_UX(1)
	ConfluxLinkPayloadLen = 50
	ConfluxSwitchLen      = 4

	ConfluxUXNoOpinion        byte = 0
	ConfluxUXMinLatency       byte = 1
	ConfluxUXLowMemLatency    byte = 2
	ConfluxUXHighThroughput   byte = 3 // C Tor 客户端默认 ConfluxClientUX=throughput
	ConfluxUXLowMemThroughput byte = 4
)

// ConfluxLink 是 LINK / LINKED 的负载（两边相同）。
type ConfluxLink struct {
	Version     byte
	Nonce       [ConfluxNonceLen]byte
	LastSeqSent uint64
	LastSeqRecv uint64
	DesiredUX   byte
}

// EncodeConfluxLink 编码 50 字节 LINK/LINKED 负载。nonce 由调用方提供，本函数不生成。
func EncodeConfluxLink(l *ConfluxLink) ([]byte, error) {
	if l == nil {
		return nil, fmt.Errorf("nil conflux link")
	}
	if l.Version != ConfluxLinkVersion {
		return nil, fmt.Errorf("unsupported conflux link version %d", l.Version)
	}
	out := make([]byte, ConfluxLinkPayloadLen)
	out[0] = l.Version
	copy(out[1:33], l.Nonce[:])
	binary.BigEndian.PutUint64(out[33:41], l.LastSeqSent)
	binary.BigEndian.PutUint64(out[41:49], l.LastSeqRecv)
	out[49] = l.DesiredUX
	return out, nil
}

// DecodeConfluxLink 解析 LINK/LINKED。未知版本或长度不足一律失败。
func DecodeConfluxLink(data []byte) (*ConfluxLink, error) {
	if len(data) < ConfluxLinkPayloadLen {
		return nil, fmt.Errorf("conflux link payload %d, want %d", len(data), ConfluxLinkPayloadLen)
	}
	if data[0] != ConfluxLinkVersion {
		return nil, fmt.Errorf("unsupported conflux link version %d", data[0])
	}
	l := &ConfluxLink{
		Version:     data[0],
		LastSeqSent: binary.BigEndian.Uint64(data[33:41]),
		LastSeqRecv: binary.BigEndian.Uint64(data[41:49]),
		DesiredUX:   data[49],
	}
	copy(l.Nonce[:], data[1:33])
	return l, nil
}

// EncodeConfluxSwitch 编码 4 字节相对序号。
func EncodeConfluxSwitch(rel uint32) []byte {
	out := make([]byte, ConfluxSwitchLen)
	binary.BigEndian.PutUint32(out, rel)
	return out
}

// DecodeConfluxSwitch 解析 SWITCH。短于 4 字节失败。
func DecodeConfluxSwitch(data []byte) (uint32, error) {
	if len(data) < ConfluxSwitchLen {
		return 0, fmt.Errorf("conflux switch payload %d, want %d", len(data), ConfluxSwitchLen)
	}
	return binary.BigEndian.Uint32(data[:ConfluxSwitchLen]), nil
}

// ConfluxShouldMultiplex 是必须保序、计入绝对序号的命令。
// 对照 proposal 329 §2.8 与 C Tor conflux_should_multiplex（含 BEGIN_DIR）。
func ConfluxShouldMultiplex(cmd byte) bool {
	switch cmd {
	case RelayBegin, RelayData, RelayEnd, RelayConnected,
		RelayResolve, RelayResolved, RelayBeginDir, RelayXon, RelayXoff:
		return true
	default:
		return false
	}
}
