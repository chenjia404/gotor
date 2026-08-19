// Package circuit — Circpad 运行时控制器（Padding=2 / proposal 302）。
//
// 负责 HS setup 机状态转移与 PADDING_NEGOTIATE 载荷构造。
// 发往第二跳的洋葱层定向加密由 SendRelayCellToHop 提供；onion 建路在
// INTRODUCE1 后调用 StartHSSetup 即可。
package circuit

import (
	"fmt"
	"sync"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// HSSetupKind 选择 intro / rend 客户端机。
type HSSetupKind int

const (
	HSSetupIntro HSSetupKind = iota
	HSSetupRend
)

// CircpadConfig 来自共识的 circpad 开关与上限。
type CircpadConfig struct {
	Disabled           bool
	GlobalAllowedCells int
}

// CircpadConfigFromParams 从 directory.GetPaddingParams 映射。
func CircpadConfigFromParams(disabled bool, globalAllowed int) CircpadConfig {
	return CircpadConfig{Disabled: disabled, GlobalAllowedCells: globalAllowed}
}

// CircpadController 管理单条电路上的 HS setup padding 机。
type CircpadController struct {
	mu         sync.Mutex
	cfg        CircpadConfig
	machine    CircpadHSSetupMachine
	kind       HSSetupKind
	state      int
	machineCtr uint32
	active     bool
	negotiateSent bool
	paddingSent   int
	paddingRecv   int
}

// NewCircpadController 创建控制器；默认 machineCtr 从 1 起。
func NewCircpadController(cfg CircpadConfig) *CircpadController {
	return &CircpadController{
		cfg:        cfg,
		state:      CircpadStateStart,
		machineCtr: 1,
	}
}

// Active 是否已启动且未结束。
func (c *CircpadController) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active && c.state != CircpadStateEnd
}

// State 当前状态（CIRCPAD_STATE_*）。
func (c *CircpadController) State() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// MachineCtr 当前机实例计数。
func (c *CircpadController) MachineCtr() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.machineCtr
}

// StartHSSetup 在电路上启动客户端 HS setup 机（需对端 Padding=2 且共识未禁用）。
func (c *CircpadController) StartHSSetup(kind HSSetupKind) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Disabled {
		return fmt.Errorf("circpad disabled by consensus")
	}
	if c.active {
		return fmt.Errorf("circpad already active")
	}
	switch kind {
	case HSSetupIntro:
		c.machine = ClientHideIntroCircuits()
	case HSSetupRend:
		c.machine = ClientHideRendCircuits()
	default:
		return fmt.Errorf("unknown HS setup kind %d", kind)
	}
	c.kind = kind
	c.state = CircpadStateStart
	c.active = true
	c.negotiateSent = false
	c.paddingSent = 0
	c.paddingRecv = 0
	return nil
}

// BuildNegotiateStart 构造发往第二跳的 PADDING_NEGOTIATE START 载荷与 RelayCell。
// 调用方应在 INTRODUCE1（或 rend 对应非 padding 信元）之后发送。
func (c *CircpadController) BuildNegotiateStart() (*cell.RelayCell, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return nil, fmt.Errorf("circpad not active")
	}
	if !c.machine.SendsNegotiate {
		return nil, fmt.Errorf("machine %s does not send negotiate", c.machine.Name)
	}
	payload, err := EncodeCircpadNegotiate(&CircpadNegotiate{
		Version:     0,
		Command:     CircpadCommandStart,
		MachineType: CircpadMachineCircSetup,
		MachineCtr:  c.machineCtr,
	})
	if err != nil {
		return nil, err
	}
	rc, err := cell.NewRelayCell(0, cell.RelayPaddingNegotiate, payload)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// OnNonpaddingSent 在发出非 padding 信元后调用（intro：INTRODUCE1；rend：negotiate 本身也算）。
func (c *CircpadController) OnNonpaddingSent() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return
	}
	c.applyEventLocked(CircpadEventNonpaddingSent)
}

// MarkNegotiateSent 在成功发出 PADDING_NEGOTIATE 后调用。
func (c *CircpadController) MarkNegotiateSent() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.negotiateSent = true
	c.applyEventLocked(CircpadEventNonpaddingSent)
}

// OnNegotiated 处理 PADDING_NEGOTIATED。
func (c *CircpadController) OnNegotiated(n *CircpadNegotiated) error {
	if n == nil {
		return fmt.Errorf("nil negotiated")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return fmt.Errorf("circpad not active")
	}
	if n.MachineCtr != c.machineCtr {
		return nil // spec：ctr 不匹配则忽略
	}
	if n.Response == CircpadResponseErr {
		c.active = false
		c.state = CircpadStateEnd
		return fmt.Errorf("circpad negotiated ERR")
	}
	// 对端已接受；intro 客户端机停留在 OBFUSCATE 等对端 DROP。
	return nil
}

// OnPaddingRecv 收到 DROP / padding 时调用（rend 客户端机可因此结束）。
func (c *CircpadController) OnPaddingRecv() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return
	}
	c.paddingRecv++
	c.applyEventLocked(CircpadEventPaddingRecv)
	if c.machine.LengthUniformMax > 0 && c.paddingRecv >= c.machine.LengthUniformMax {
		c.applyEventLocked(CircpadEventLengthCount)
	}
}

// Stop 发送 STOP 并结束。
func (c *CircpadController) Stop() (*cell.RelayCell, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return nil, nil
	}
	payload, err := EncodeCircpadNegotiate(&CircpadNegotiate{
		Version:     0,
		Command:     CircpadCommandStop,
		MachineType: CircpadMachineCircSetup,
		MachineCtr:  c.machineCtr,
	})
	if err != nil {
		return nil, err
	}
	rc, err := cell.NewRelayCell(0, cell.RelayPaddingNegotiate, payload)
	c.active = false
	c.state = CircpadStateEnd
	c.machineCtr++
	return rc, err
}

func (c *CircpadController) applyEventLocked(event int) {
	next := c.machine.NextState(c.state, event)
	if next < 0 {
		return
	}
	c.state = next
	if c.state == CircpadStateEnd {
		c.active = false
	}
}

// NegotiateSent 是否已发出 START negotiate。
func (c *CircpadController) NegotiateSent() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.negotiateSent
}

// Kind 返回当前机种类。
func (c *CircpadController) Kind() HSSetupKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kind
}

// TargetHop 返回协商目标跳（1-based，setup 机为 2）。
func (c *CircpadController) TargetHop() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return 0
	}
	return c.machine.TargetHop
}
