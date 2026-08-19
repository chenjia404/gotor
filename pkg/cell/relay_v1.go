package cell

import (
	"encoding/binary"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/security"
)

// CGO / proposal 340 的 v1 relay message。对照 C Tor relay_msg.c：
//
//	payload[0:16]   CGO tag（编码时留空，由 CGO originate 填 N）
//	payload[16]     command
//	payload[17:19]  length（仅 data，不含 stream_id）
//	payload[19:21]  stream_id（仅部分命令）
//	payload[21 或 19:] data
//	其后 4 字节 0 + 随机填充
const (
	RelayXon  byte = 43
	RelayXoff byte = 44

	v1CmdOffset           = 16
	v1LenOffset           = 17
	v1StreamIDOffset      = 19
	v1PayloadNoStreamID   = 19
	v1PayloadWithStreamID = 21

	// RelayHeaderSizeV1* 对照 C Tor RELAY_HEADER_SIZE_V1_*。
	RelayHeaderSizeV1NoStreamID   = 19
	RelayHeaderSizeV1WithStreamID = 21
)

// RelayCellMaxDataV1 是 v1 一条消息的最大 data 长度（C Tor relay_cell_max_payload_size）。
// DATA 带 stream_id：509-21=488，不是 v0 的 498。
func RelayCellMaxDataV1(cmd byte) int {
	if RelayCmdExpectsStreamID(cmd) {
		return PayloadLen - RelayHeaderSizeV1WithStreamID
	}
	return PayloadLen - RelayHeaderSizeV1NoStreamID
}

// RelayCmdExpectsStreamID 是 v1 里必须带非 0 StreamID 的命令。
func RelayCmdExpectsStreamID(cmd byte) bool {
	switch cmd {
	case RelayBegin, RelayData, RelayEnd, RelayConnected,
		RelayResolve, RelayResolved, RelayBeginDir, RelayXon, RelayXoff:
		return true
	default:
		return false
	}
}

// EncodeRelayCellV1 把消息编进 509 字节 payload。前 16 字节保持 0 给 CGO。
func EncodeRelayCellV1(rc *RelayCell) ([]byte, error) {
	if rc == nil {
		return nil, fmt.Errorf("nil relay cell")
	}
	payload := make([]byte, PayloadLen)
	off := v1PayloadNoStreamID
	if RelayCmdExpectsStreamID(rc.Command) {
		if rc.StreamID == 0 {
			return nil, fmt.Errorf("v1 command %d requires nonzero stream_id", rc.Command)
		}
		binary.BigEndian.PutUint16(payload[v1StreamIDOffset:v1StreamIDOffset+2], rc.StreamID)
		off = v1PayloadWithStreamID
	} else if rc.StreamID != 0 {
		return nil, fmt.Errorf("v1 command %d must have stream_id 0", rc.Command)
	}
	length, err := security.SafeLenToUint16(rc.Data)
	if err != nil {
		return nil, fmt.Errorf("v1 data too large: %w", err)
	}
	if off+int(length) > PayloadLen {
		return nil, fmt.Errorf("v1 data %d does not fit after header %d", length, off)
	}
	payload[v1CmdOffset] = rc.Command
	binary.BigEndian.PutUint16(payload[v1LenOffset:v1LenOffset+2], length)
	copy(payload[off:], rc.Data)
	rc.Length = length
	return payload, nil
}

// DecodeRelayCellV1 从 509 字节 CGO 明文解出消息。
func DecodeRelayCellV1(payload []byte) (*RelayCell, error) {
	if len(payload) < PayloadLen {
		return nil, fmt.Errorf("v1 payload length %d, want %d", len(payload), PayloadLen)
	}
	rc := &RelayCell{
		Command: payload[v1CmdOffset],
		Length:  binary.BigEndian.Uint16(payload[v1LenOffset : v1LenOffset+2]),
	}
	off := v1PayloadNoStreamID
	if RelayCmdExpectsStreamID(rc.Command) {
		rc.StreamID = binary.BigEndian.Uint16(payload[v1StreamIDOffset : v1StreamIDOffset+2])
		off = v1PayloadWithStreamID
	}
	if int(rc.Length) > len(payload)-off {
		return nil, fmt.Errorf("v1 length %d exceeds remaining %d", rc.Length, len(payload)-off)
	}
	if rc.Length > 0 {
		rc.Data = append([]byte(nil), payload[off:off+int(rc.Length)]...)
	}
	return rc, nil
}

// V1MessageEnd 返回消息结束偏移（不含 4 字节零填充），供随机填充。
func V1MessageEnd(payload []byte) int {
	if len(payload) < v1PayloadNoStreamID {
		return len(payload)
	}
	cmd := payload[v1CmdOffset]
	length := int(binary.BigEndian.Uint16(payload[v1LenOffset : v1LenOffset+2]))
	off := v1PayloadNoStreamID
	if RelayCmdExpectsStreamID(cmd) {
		off = v1PayloadWithStreamID
	}
	end := off + length
	if end > len(payload) {
		return len(payload)
	}
	return end
}
