// Package relay — 扩展电路注册、剥层转发与回程投递。
package relay

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/connection"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// ExtendedCircuit tracks a circuit that has been extended to next hop
type ExtendedCircuit struct {
	ClientCircuitID  uint32
	NextHopCircuitID uint32
	NextHopAddress   string
	NextHopOR        *connection.Connection // 优先：经 SendCell 同步写
	NextHopConn      net.Conn               // 测试桩 / 无 Connection 时的回退
	ClientConn       net.Conn               // 入向 OR，回程加密后写回
	RelayEarlyCount  int
	mu               sync.Mutex
}

func (ext *ExtendedCircuit) sendToNextHop(c *cell.Cell) error {
	if ext == nil {
		return fmt.Errorf("nil extended circuit")
	}
	if ext.NextHopOR != nil {
		return ext.NextHopOR.SendCell(c)
	}
	if ext.NextHopConn != nil {
		return c.Encode(ext.NextHopConn)
	}
	return fmt.Errorf("no next-hop connection")
}

// ForwardingHandler manages cell forwarding between circuits
type ForwardingHandler struct {
	circuits   *CircuitHandler
	extended   map[uint32]*ExtendedCircuit // client circuit ID → extension
	extendedMu sync.RWMutex
	logger     *logger.Logger

	hsMu         sync.Mutex
	introByAuth  map[string]*hsRoleSlot // hex(AUTH_KEY) → 服务侧引言电路
	rendByCookie map[string]*hsRoleSlot // hex(cookie) → 客户端会合电路
}

type hsRoleSlot struct {
	circ *ServerCircuit
	conn net.Conn
}

// NewForwardingHandler creates a new forwarding handler
func NewForwardingHandler(circuits *CircuitHandler, log *logger.Logger) *ForwardingHandler {
	if log == nil {
		log = logger.NewDefault()
	}
	return &ForwardingHandler{
		circuits:     circuits,
		extended:     make(map[uint32]*ExtendedCircuit),
		introByAuth:  make(map[string]*hsRoleSlot),
		rendByCookie: make(map[string]*hsRoleSlot),
		logger:       log.Component("forwarding"),
	}
}

// RegisterExtendedCircuit 兼容旧测试（仅 net.Conn，无回程泵）。
func (h *ForwardingHandler) RegisterExtendedCircuit(clientCircID, nextHopCircID uint32, nextHopAddr string, nextHopConn net.Conn) error {
	return h.registerExtended(clientCircID, nextHopCircID, nextHopAddr, nil, nextHopConn, nil)
}

// RegisterExtendedCircuitOR 注册真实出站 Connection 与入向 clientConn，供回程投递。
func (h *ForwardingHandler) RegisterExtendedCircuitOR(clientCircID, nextHopCircID uint32, nextHopAddr string, nextOR *connection.Connection, clientConn net.Conn) error {
	return h.registerExtended(clientCircID, nextHopCircID, nextHopAddr, nextOR, nil, clientConn)
}

func (h *ForwardingHandler) registerExtended(clientCircID, nextHopCircID uint32, nextHopAddr string, nextOR *connection.Connection, nextNet net.Conn, clientConn net.Conn) error {
	h.extendedMu.Lock()
	defer h.extendedMu.Unlock()

	if _, exists := h.extended[clientCircID]; exists {
		return fmt.Errorf("circuit %d already extended", clientCircID)
	}

	h.extended[clientCircID] = &ExtendedCircuit{
		ClientCircuitID:  clientCircID,
		NextHopCircuitID: nextHopCircID,
		NextHopAddress:   nextHopAddr,
		NextHopOR:        nextOR,
		NextHopConn:      nextNet,
		ClientConn:       clientConn,
		RelayEarlyCount:  0,
	}

	h.logger.Info("Registered extended circuit",
		"client_circuit_id", clientCircID,
		"next_hop_circuit_id", nextHopCircID,
		"next_hop_address", nextHopAddr)

	return nil
}

// DeliverFromNextHop 由共享出站链路上的读循环调用，按 CircID 投递回客户端。
func (h *ForwardingHandler) DeliverFromNextHop(nextHopAddr string, c *cell.Cell) {
	if c == nil {
		return
	}
	h.extendedMu.RLock()
	var ext *ExtendedCircuit
	for _, e := range h.extended {
		if e.NextHopAddress == nextHopAddr && e.NextHopCircuitID == c.CircID {
			ext = e
			break
		}
	}
	h.extendedMu.RUnlock()
	if ext == nil {
		return
	}
	if err := h.forwardCellToClient(ext, c); err != nil {
		h.logger.Debug("forward to client failed", "error", err, "circuit_id", ext.ClientCircuitID)
	}
	if c.Command == cell.CmdDestroy {
		// 下一跳已拆除：先摘映射再关入站电路，避免再向下一跳发 DESTROY。
		h.extendedMu.Lock()
		delete(h.extended, ext.ClientCircuitID)
		h.extendedMu.Unlock()
		if h.circuits != nil {
			h.circuits.CloseCircuit(ext.ClientCircuitID)
		}
	}
}

// ForwardRelayCell forwards a relay cell from client to next hop
func (h *ForwardingHandler) ForwardRelayCell(ctx context.Context, fromClient bool, circuitID uint32, c *cell.Cell, clientConn net.Conn) error {
	h.extendedMu.RLock()
	ext, isExtended := h.extended[circuitID]
	h.extendedMu.RUnlock()

	if !isExtended {
		return h.handleLocalRelayCell(ctx, circuitID, c, clientConn)
	}

	if fromClient {
		// 记住入向连接供回程使用
		if clientConn != nil {
			ext.mu.Lock()
			if ext.ClientConn == nil {
				ext.ClientConn = clientConn
			}
			ext.mu.Unlock()
		}
		return h.forwardExtendedFromClient(ctx, ext, circuitID, c, clientConn)
	}
	return h.forwardCellToClient(ext, c)
}

// forwardExtendedFromClient 解密本跳后转发或本跳处理。
func (h *ForwardingHandler) forwardExtendedFromClient(ctx context.Context, ext *ExtendedCircuit, circuitID uint32, c *cell.Cell, clientConn net.Conn) error {
	circ, ok := h.circuits.GetCircuit(circuitID)
	if !ok || circ == nil || circ.crypto == nil {
		return h.forwardOpaqueToNextHop(ext, c)
	}
	peeled, forUs, digest, err := circ.crypto.peelInboundWithAD(c.Payload, cgoAD(c.Command))
	if err != nil {
		return err
	}
	if forUs {
		if h.circuits.exits != nil {
			h.circuits.exits.NoteFwdDigest(circuitID, digest)
		}
		relayCell, err := circ.crypto.decodeRelay(peeled)
		if err != nil {
			return fmt.Errorf("invalid local relay cell: %w", err)
		}
		switch relayCell.Command {
		case cell.RelaySendme:
			if h.circuits.exits != nil {
				h.circuits.exits.HandleSendme(circuitID, relayCell.StreamID, relayCell.Data)
			}
			return nil
		case cell.RelayTruncate:
			return h.handleTruncate(circuitID)
		case cell.RelayExtend2:
			return fmt.Errorf("circuit already extended")
		default:
			h.logger.Debug("local command on extended circuit", "cmd", cell.RelayCmdString(relayCell.Command))
			return nil
		}
	}
	fwd := &cell.Cell{
		CircID:  ext.NextHopCircuitID,
		Command: c.Command,
		Payload: peeled,
	}
	if c.Command == cell.CmdRelayEarly {
		ext.mu.Lock()
		if ext.RelayEarlyCount >= 8 {
			fwd.Command = cell.CmdRelay
		} else {
			ext.RelayEarlyCount++
		}
		ext.mu.Unlock()
	}
	return ext.sendToNextHop(fwd)
}

func (h *ForwardingHandler) forwardOpaqueToNextHop(ext *ExtendedCircuit, c *cell.Cell) error {
	fwd := &cell.Cell{
		CircID:  ext.NextHopCircuitID,
		Command: c.Command,
		Payload: c.Payload,
	}
	if c.Command == cell.CmdRelayEarly {
		ext.mu.Lock()
		if ext.RelayEarlyCount >= 8 {
			fwd.Command = cell.CmdRelay
		} else {
			ext.RelayEarlyCount++
		}
		ext.mu.Unlock()
	}
	return ext.sendToNextHop(fwd)
}

// forwardToNextHop 保留旧名供测试调用。
func (h *ForwardingHandler) forwardToNextHop(ext *ExtendedCircuit, c *cell.Cell) error {
	return h.forwardOpaqueToNextHop(ext, c)
}

// forwardCellToClient 将下一跳 cell 加密（RELAY）后写回入向连接。
func (h *ForwardingHandler) forwardCellToClient(ext *ExtendedCircuit, c *cell.Cell) error {
	ext.mu.Lock()
	clientConn := ext.ClientConn
	ext.mu.Unlock()
	if clientConn == nil {
		return fmt.Errorf("no client connection for circuit %d", ext.ClientCircuitID)
	}

	outCmd := c.Command
	payload := c.Payload

	switch c.Command {
	case cell.CmdRelay, cell.CmdRelayEarly:
		circ, ok := h.circuits.GetCircuit(ext.ClientCircuitID)
		if !ok || circ == nil || circ.crypto == nil {
			return fmt.Errorf("circuit crypto unavailable for return path")
		}
		if len(payload) != 509 {
			return fmt.Errorf("invalid relay payload len %d", len(payload))
		}
		enc, err := circ.crypto.wrapOutbound(payload, cgoAD(c.Command))
		if err != nil {
			return err
		}
		payload = enc
		outCmd = cell.CmdRelay
	case cell.CmdDestroy:
		// 透传 DESTROY
	default:
		// 其它固定长度 cell 透传（改 CircID）
	}

	out := &cell.Cell{
		CircID:  ext.ClientCircuitID,
		Command: outCmd,
		Payload: payload,
	}
	return out.Encode(clientConn)
}

// forwardToClient 兼容旧占位调用。
func (h *ForwardingHandler) forwardToClient(ext *ExtendedCircuit, c *cell.Cell) error {
	return h.forwardCellToClient(ext, c)
}
