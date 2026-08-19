package cell

import (
	"encoding/binary"
	"fmt"
)

// SENDME 负载格式见 tor-spec flow-control：
//
//	VERSION   [1]
//	DATA_LEN  [2]
//	DATA      [DATA_LEN]
//
// 电路级 SENDME（StreamID=0）在现代网络必须发 version 1。
// 流级 SENDME（StreamID≠0）仍为空，接收方忽略 body。
const (
	SendmeVersion0     byte = 0
	SendmeVersion1     byte = 1
	SendmeV1DigestLen       = 20
	sendmeV1PayloadLen      = 1 + 2 + SendmeV1DigestLen
)

// EncodeSendmeV1 编码认证 SENDME：VERSION=1, DATA_LEN=20, DIGEST=20 字节滚动摘要。
func EncodeSendmeV1(digest []byte) ([]byte, error) {
	if len(digest) != SendmeV1DigestLen {
		return nil, fmt.Errorf("SENDME v1 digest must be %d bytes, got %d", SendmeV1DigestLen, len(digest))
	}
	out := make([]byte, sendmeV1PayloadLen)
	out[0] = SendmeVersion1
	binary.BigEndian.PutUint16(out[1:3], uint16(SendmeV1DigestLen))
	copy(out[3:], digest)
	return out, nil
}

// DecodeSendme 解析电路级 SENDME。空负载视为 version 0。
func DecodeSendme(payload []byte) (version byte, digest []byte, err error) {
	if len(payload) == 0 {
		return SendmeVersion0, nil, nil
	}
	if len(payload) < 3 {
		return 0, nil, fmt.Errorf("SENDME payload too short: %d", len(payload))
	}
	version = payload[0]
	dataLen := int(binary.BigEndian.Uint16(payload[1:3]))
	if 3+dataLen > len(payload) {
		return version, nil, fmt.Errorf("SENDME DATA_LEN %d exceeds payload %d", dataLen, len(payload))
	}
	data := payload[3 : 3+dataLen]
	switch version {
	case SendmeVersion0:
		return version, nil, nil
	case SendmeVersion1:
		if dataLen < SendmeV1DigestLen {
			return version, nil, fmt.Errorf("SENDME v1 DATA_LEN %d < 20", dataLen)
		}
		return version, append([]byte(nil), data[:SendmeV1DigestLen]...), nil
	default:
		return version, nil, fmt.Errorf("unrecognized SENDME version %d", version)
	}
}
