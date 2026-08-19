// Package circuit — Padding=2 / proposal 302 HS circuit setup machines。
//
// 对照：
//   - padding-spec circuit-level-padding（PADDING_NEGOTIATE / NEGOTIATED）
//   - proposal 302；C Tor circuitpadding_machines.c / circuitpadding_machines.h
package circuit

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// CIRCPAD 命令 / 响应 / 机型（padding-spec）。
const (
	CircpadCommandStop  byte = 1
	CircpadCommandStart byte = 2

	CircpadResponseOK  byte = 1
	CircpadResponseErr byte = 2

	CircpadMachineCircSetup byte = 1
)

// Intro 机 DROPs 数量（C Tor INTRO_MACHINE_MINIMUM/MAXIMUM_PADDING）。
const (
	IntroMachineMinPadding = 7
	IntroMachineMaxPadding = 10
)

// Circpad 事件与状态（WTF-PAD / C Tor circpad_event_t / circpad_state_t 子集）。
const (
	CircpadEventNonpaddingRecv = 0
	CircpadEventNonpaddingSent = 1
	CircpadEventPaddingSent    = 2
	CircpadEventPaddingRecv    = 3
	CircpadEventLengthCount    = 5

	CircpadStateStart            = 0
	CircpadStateObfuscateCircSetup = 1
	CircpadStateEnd              = 2
)

// CircpadNegotiate 是 RELAY PADDING_NEGOTIATE（cmd=41）载荷。
//
//	u8 version (=0)
//	u8 command (STOP=1 / START=2)
//	u8 machine_type (CIRC_SETUP=1)
//	u8 unused (=0)
//	u32 machine_ctr (网络序)
type CircpadNegotiate struct {
	Version     byte
	Command     byte
	MachineType byte
	Unused      byte
	MachineCtr  uint32
}

// CircpadNegotiated 是 RELAY PADDING_NEGOTIATED（cmd=42）载荷。
//
//	u8 version (=0)
//	u8 command (STOP=1 / START=2)
//	u8 response (OK=1 / ERR=2)
//	u8 machine_type
//	u32 machine_ctr
type CircpadNegotiated struct {
	Version     byte
	Command     byte
	Response    byte
	MachineType byte
	MachineCtr  uint32
}

// EncodeCircpadNegotiate 编码 8 字节 negotiate 载荷。
func EncodeCircpadNegotiate(n *CircpadNegotiate) ([]byte, error) {
	if n == nil {
		return nil, errors.New("circpad negotiate is nil")
	}
	if n.Command != CircpadCommandStart && n.Command != CircpadCommandStop {
		return nil, fmt.Errorf("invalid circpad command %d", n.Command)
	}
	out := make([]byte, 8)
	out[0] = n.Version
	out[1] = n.Command
	out[2] = n.MachineType
	out[3] = n.Unused
	binary.BigEndian.PutUint32(out[4:8], n.MachineCtr)
	return out, nil
}

// DecodeCircpadNegotiate 解码 negotiate 载荷（至少 8 字节）。
func DecodeCircpadNegotiate(data []byte) (*CircpadNegotiate, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("circpad negotiate too short: %d < 8", len(data))
	}
	return &CircpadNegotiate{
		Version:     data[0],
		Command:     data[1],
		MachineType: data[2],
		Unused:      data[3],
		MachineCtr:  binary.BigEndian.Uint32(data[4:8]),
	}, nil
}

// EncodeCircpadNegotiated 编码 8 字节 negotiated 载荷。
func EncodeCircpadNegotiated(n *CircpadNegotiated) ([]byte, error) {
	if n == nil {
		return nil, errors.New("circpad negotiated is nil")
	}
	if n.Response != CircpadResponseOK && n.Response != CircpadResponseErr {
		return nil, fmt.Errorf("invalid circpad response %d", n.Response)
	}
	out := make([]byte, 8)
	out[0] = n.Version
	out[1] = n.Command
	out[2] = n.Response
	out[3] = n.MachineType
	binary.BigEndian.PutUint32(out[4:8], n.MachineCtr)
	return out, nil
}

// DecodeCircpadNegotiated 解码 negotiated 载荷。
func DecodeCircpadNegotiated(data []byte) (*CircpadNegotiated, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("circpad negotiated too short: %d < 8", len(data))
	}
	return &CircpadNegotiated{
		Version:     data[0],
		Command:     data[1],
		Response:    data[2],
		MachineType: data[3],
		MachineCtr:  binary.BigEndian.Uint32(data[4:8]),
	}, nil
}

// CircpadTransition 描述「当前状态 + 事件 → 下一状态」。
type CircpadTransition struct {
	From  int
	Event int
	To    int
}

// CircpadHSSetupMachine 是 proposal 302 / C Tor 的 HS setup 机定义（仅客户端侧表）。
// 运行时接线（发 DROP / 与 onion 建路耦合）在 Onion Phase 完成；此处保证状态表合规。
type CircpadHSSetupMachine struct {
	Name                 string
	TargetHop            int // 1=guard, 2=middle（setup 机协商到第二跳）
	AllowedPaddingCount  int
	Transitions          []CircpadTransition
	// OriginSide：客户端机；false 表示中继侧表（我们只实现客户端协商，表仍保留对照）。
	OriginSide bool
	// SendsNegotiate：origin intro 机在 INTRODUCE1 后发 PADDING_NEGOTIATE。
	SendsNegotiate bool
	// LengthUniformMin/Max：OBFUSCATE 状态长度均匀分布（cell 数）；0 表示不适用。
	LengthUniformMin int
	LengthUniformMax int
}

// ClientHideIntroCircuits 对照 circpad_machine_client_hide_intro_circuits。
// START --NONPADDING_SENT--> OBFUSCATE；客户端不发 DROP，只发 negotiate。
func ClientHideIntroCircuits() CircpadHSSetupMachine {
	return CircpadHSSetupMachine{
		Name:                "client_hide_intro",
		TargetHop:           2,
		AllowedPaddingCount: IntroMachineMaxPadding,
		OriginSide:          true,
		SendsNegotiate:      true,
		Transitions: []CircpadTransition{
			{From: CircpadStateStart, Event: CircpadEventNonpaddingSent, To: CircpadStateObfuscateCircSetup},
		},
	}
}

// RelayHideIntroCircuits 对照中继侧 intro 机（状态表；客户端库用于校验/文档）。
func RelayHideIntroCircuits() CircpadHSSetupMachine {
	return CircpadHSSetupMachine{
		Name:                "relay_hide_intro",
		TargetHop:           2,
		AllowedPaddingCount: IntroMachineMaxPadding,
		OriginSide:          false,
		LengthUniformMin:    IntroMachineMinPadding,
		LengthUniformMax:    IntroMachineMaxPadding,
		Transitions: []CircpadTransition{
			{From: CircpadStateStart, Event: CircpadEventNonpaddingSent, To: CircpadStateObfuscateCircSetup},
			{From: CircpadStateObfuscateCircSetup, Event: CircpadEventLengthCount, To: CircpadStateEnd},
			{From: CircpadStateObfuscateCircSetup, Event: CircpadEventPaddingSent, To: CircpadStateObfuscateCircSetup},
			{From: CircpadStateObfuscateCircSetup, Event: CircpadEventNonpaddingSent, To: CircpadStateObfuscateCircSetup},
		},
	}
}

// ClientHideRendCircuits 对照 circpad_machine_client_hide_rend_circuits。
func ClientHideRendCircuits() CircpadHSSetupMachine {
	return CircpadHSSetupMachine{
		Name:                "client_hide_rend",
		TargetHop:           2,
		AllowedPaddingCount: IntroMachineMaxPadding,
		OriginSide:          true,
		SendsNegotiate:      true,
		LengthUniformMin:    1,
		LengthUniformMax:    1,
		Transitions: []CircpadTransition{
			{From: CircpadStateStart, Event: CircpadEventNonpaddingSent, To: CircpadStateObfuscateCircSetup},
			{From: CircpadStateObfuscateCircSetup, Event: CircpadEventPaddingRecv, To: CircpadStateEnd},
			{From: CircpadStateObfuscateCircSetup, Event: CircpadEventLengthCount, To: CircpadStateEnd},
		},
	}
}

// NextState 查表；无匹配返回 -1。
func (m CircpadHSSetupMachine) NextState(from, event int) int {
	for _, tr := range m.Transitions {
		if tr.From == from && tr.Event == event {
			return tr.To
		}
	}
	return -1
}

// CircpadPaddingDisabled 读共识 circpad_padding_disabled（缺省 0=启用）。
func CircpadPaddingDisabled(params map[string]int) bool {
	if params == nil {
		return false
	}
	return params["circpad_padding_disabled"] != 0
}
