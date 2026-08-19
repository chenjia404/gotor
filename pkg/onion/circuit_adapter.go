// Package onion — 电路构建 / cell 发送适配器（对接 pkg/circuit）。
package onion

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
)

// CircuitAdapter 实现 CircuitBuilder + CellSender，用 3-hop 电路到达目标 OR。
type CircuitAdapter struct {
	builder *circuit.Builder
	manager *circuit.Manager
	relays  []*directory.Relay
	logger  *logger.Logger
	circs   map[uint32]*circuit.Circuit
}

// NewCircuitAdapter 创建适配器。
func NewCircuitAdapter(builder *circuit.Builder, manager *circuit.Manager, relays []*directory.Relay, log *logger.Logger) *CircuitAdapter {
	if log == nil {
		log = logger.NewDefault()
	}
	return &CircuitAdapter{
		builder: builder,
		manager: manager,
		relays:  relays,
		logger:  log.Component("onion-circ"),
		circs:   make(map[uint32]*circuit.Circuit),
	}
}

// SetRelays 更新共识节点池。
func (a *CircuitAdapter) SetRelays(relays []*directory.Relay) {
	a.relays = relays
}

// BuildCircuitToRelay 建 Guard→Middle→relay 三跳。
func (a *CircuitAdapter) BuildCircuitToRelay(ctx context.Context, target *HSDirectory, timeout time.Duration) (uint32, error) {
	if a == nil || a.builder == nil {
		return 0, fmt.Errorf("circuit adapter not configured")
	}
	exit := a.resolveTarget(target)
	if exit == nil || !exit.HasExtendKeys() {
		return 0, fmt.Errorf("target relay missing extend keys")
	}
	p, err := a.pickPath(exit)
	if err != nil {
		return 0, err
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	var circ *circuit.Circuit
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			p, err = a.pickPath(exit)
			if err != nil {
				return 0, err
			}
		}
		circ, last = a.builder.BuildCircuit(ctx, p, timeout)
		if last == nil {
			break
		}
		a.logger.Debug("path build failed", "attempt", attempt+1, "error", last)
	}
	if circ == nil {
		return 0, fmt.Errorf("build circuit to %s: %w", exit.Nickname, last)
	}
	a.circs[circ.ID] = circ
	return circ.ID, nil
}

func (a *CircuitAdapter) resolveTarget(h *HSDirectory) *directory.Relay {
	if h == nil {
		return nil
	}
	if h.Relay != nil && h.Relay.HasExtendKeys() {
		return h.Relay
	}
	for _, r := range a.relays {
		if r == nil {
			continue
		}
		fp := r.GetFingerprintHex()
		if h.Fingerprint != "" && (fp == h.Fingerprint || r.Fingerprint == h.Fingerprint) {
			return r
		}
		if h.Address != "" && r.Address == h.Address && (h.ORPort == 0 || r.ORPort == h.ORPort) {
			return r
		}
	}
	return nil
}

func (a *CircuitAdapter) pickPath(exit *directory.Relay) (*path.Path, error) {
	guards := make([]*directory.Relay, 0, 32)
	middles := make([]*directory.Relay, 0, 64)
	for _, r := range a.relays {
		if r == nil || !r.IsRunning() || !r.IsValid() || !r.HasExtendKeys() {
			continue
		}
		if sameRelay(r, exit) {
			continue
		}
		if r.IsGuard() {
			guards = append(guards, r)
		}
		middles = append(middles, r)
	}
	if len(guards) == 0 || len(middles) == 0 {
		return nil, fmt.Errorf("insufficient path relays")
	}
	for try := 0; try < 48; try++ {
		g := guards[rand.Intn(len(guards))]
		m := middles[rand.Intn(len(middles))]
		if sameRelay(g, m) || sameRelay(m, exit) {
			continue
		}
		if g.InSameFamily(m) || g.InSameFamily(exit) || m.InSameFamily(exit) {
			continue
		}
		return &path.Path{Guard: g, Middle: m, Exit: exit}, nil
	}
	return &path.Path{Guard: guards[0], Middle: middles[0], Exit: exit}, nil
}

func (a *CircuitAdapter) lookup(circuitID uint32) *circuit.Circuit {
	if c := a.circs[circuitID]; c != nil {
		return c
	}
	if a.manager != nil {
		if c, err := a.manager.GetCircuit(circuitID); err == nil {
			return c
		}
	}
	return nil
}

// SendRelayCell 在已建电路上发送 relay cell。
func (a *CircuitAdapter) SendRelayCell(ctx context.Context, circuitID uint32, command uint8, data []byte) error {
	circ := a.lookup(circuitID)
	if circ == nil {
		return fmt.Errorf("circuit %d not found", circuitID)
	}
	rc, err := cell.NewRelayCell(0, command, data)
	if err != nil {
		return err
	}
	return circ.SendRelayCell(rc)
}

// ReceiveRelayCell 等待指定电路上的下一则 relay cell 载荷。
func (a *CircuitAdapter) ReceiveRelayCell(ctx context.Context, circuitID uint32, timeout time.Duration) ([]byte, error) {
	circ := a.lookup(circuitID)
	if circ == nil {
		return nil, fmt.Errorf("circuit %d not found", circuitID)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	rc, err := circ.ReceiveRelayCell(ctx)
	if err != nil {
		return nil, err
	}
	// 返回 command||data 或仅 data？现有 WaitForRendezvous2 期望握手数据。
	// 将 command 放首位便于过滤，但旧接口只返回 data。
	_ = rc.Command
	return rc.Data, nil
}

// GetCircuit 返回本地缓存的电路。
func (a *CircuitAdapter) GetCircuit(id uint32) *circuit.Circuit {
	return a.lookup(id)
}
