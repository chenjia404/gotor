// Package relay - Cell forwarding for relay servers
// This file implements relay cell forwarding per tor-spec.txt §5.5-5.6
package relay

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// handleLocalRelayCell handles relay cells for circuits that end at this relay
func (h *ForwardingHandler) handleLocalRelayCell(ctx context.Context, circuitID uint32, c *cell.Cell, clientConn net.Conn) error {
	circ, ok := h.circuits.GetCircuit(circuitID)
	if !ok || circ == nil || circ.crypto == nil {
		return fmt.Errorf("circuit %d crypto unavailable", circuitID)
	}
	plain, digest, err := circ.crypto.decryptInboundWithAD(c.Payload, cgoAD(c.Command))
	if err != nil {
		if strings.Contains(err.Error(), "digest mismatch") {
			h.logger.Warn("relay digest mismatch, destroying circuit", "circuit_id", circuitID)
			if clientConn != nil {
				_ = h.circuits.sendDestroyCell(clientConn, circuitID, cell.DestroyReasonProtocol)
			}
			h.circuits.CloseCircuit(circuitID)
			return err
		}
		h.logger.Debug("drop unrecognized relay cell", "circuit_id", circuitID, "error", err)
		return nil
	}
	if h.circuits.exits != nil {
		h.circuits.exits.NoteFwdDigest(circuitID, digest)
	}
	relayCell, err := circ.crypto.decodeRelay(plain)
	if err != nil {
		return fmt.Errorf("invalid relay cell: %w", err)
	}

	circ.mu.RLock()
	joined := circ.joinedCirc
	joinedConn := circ.joinedConn
	circ.mu.RUnlock()
	if joined != nil && joinedConn != nil {
		return sendRelayToClient(joined, joinedConn, relayCell.StreamID, relayCell.Command, relayCell.Data)
	}

	h.logger.Debug("Handling local relay cell",
		"circuit_id", circuitID,
		"command", cell.RelayCmdString(relayCell.Command),
		"stream_id", relayCell.StreamID)

	switch relayCell.Command {
	case cell.RelayBegin:
		if err := h.refuseSingleHopIfNeeded(circ, clientConn); err != nil {
			return err
		}
		if h.circuits.exits == nil {
			return h.rejectExitAttempt(circ, clientConn, relayCell.StreamID)
		}
		return h.circuits.exits.HandleBegin(ctx, circ, clientConn, relayCell.StreamID, relayCell.Data)

	case cell.RelayBeginDir:
		if err := h.refuseSingleHopIfNeeded(circ, clientConn); err != nil {
			return err
		}
		if h.circuits.exits == nil {
			return h.rejectExitAttempt(circ, clientConn, relayCell.StreamID)
		}
		return h.circuits.exits.HandleBeginDir(ctx, circ, clientConn, relayCell.StreamID)

	case cell.RelayResolve:
		if err := h.refuseSingleHopIfNeeded(circ, clientConn); err != nil {
			return err
		}
		if h.circuits.exits == nil {
			return h.rejectExitAttempt(circ, clientConn, relayCell.StreamID)
		}
		return h.circuits.exits.HandleResolve(ctx, circ, clientConn, relayCell.StreamID, relayCell.Data)

	case cell.RelayData:
		if h.circuits.exits != nil {
			return h.circuits.exits.HandleData(circ, clientConn, relayCell.StreamID, relayCell.Data)
		}
		return nil

	case cell.RelaySendme:
		if h.circuits.exits != nil {
			h.circuits.exits.HandleSendme(circuitID, relayCell.StreamID, relayCell.Data)
		}
		return nil

	case cell.RelayEnd:
		if h.circuits.exits != nil {
			h.circuits.exits.HandleEnd(circuitID, relayCell.StreamID)
		}
		return nil

	case cell.RelayExtend2:
		if h.circuits.extender == nil {
			return fmt.Errorf("extension handler unavailable")
		}
		return h.circuits.extender.HandleExtend2(ctx, circuitID, relayCell, clientConn)

	case cell.RelayTruncate:
		return h.handleTruncate(circuitID)

	case cell.RelayEstablishIntro:
		if relayCell.StreamID != 0 {
			return h.rejectHSControlStream(circ, clientConn, "ESTABLISH_INTRO")
		}
		return h.handleEstablishIntro(circ, clientConn, relayCell.Data)

	case cell.RelayEstablishRendezvous:
		if relayCell.StreamID != 0 {
			return h.rejectHSControlStream(circ, clientConn, "ESTABLISH_RENDEZVOUS")
		}
		return h.handleEstablishRendezvous(circ, clientConn, relayCell.Data)

	case cell.RelayIntroduce1:
		if relayCell.StreamID != 0 {
			return h.rejectHSControlStream(circ, clientConn, "INTRODUCE1")
		}
		return h.handleIntroduce1(circ, clientConn, relayCell.Data)

	case cell.RelayRendezvous1:
		if relayCell.StreamID != 0 {
			return h.rejectHSControlStream(circ, clientConn, "RENDEZVOUS1")
		}
		return h.handleRendezvous1(circ, clientConn, relayCell.Data)

	default:
		return nil
	}
}

func (h *ForwardingHandler) refuseSingleHopIfNeeded(circ *ServerCircuit, clientConn net.Conn) error {
	if h.circuits == nil || h.circuits.dos == nil || !h.circuits.dos.RefuseSingleHop() {
		return nil
	}
	circ.mu.RLock()
	extended := circ.didExtend
	circ.mu.RUnlock()
	if extended {
		return nil
	}
	h.logger.Warn("DoSRefuseSingleHopClient: DESTROY", "circuit_id", circ.CircuitID)
	if clientConn != nil {
		_ = h.circuits.sendDestroyCell(clientConn, circ.CircuitID, cell.DestroyReasonProtocol)
	}
	h.circuits.CloseCircuit(circ.CircuitID)
	return fmt.Errorf("single-hop client refused")
}

// rejectExitAttempt sends RELAY_END with EXITPOLICY reason
func (h *ForwardingHandler) rejectExitAttempt(circ *ServerCircuit, clientConn net.Conn, streamID uint16) error {
	h.logger.Info("Rejecting exit attempt (exit policy)",
		"circuit_id", circ.CircuitID,
		"stream_id", streamID)
	if circ.crypto == nil || clientConn == nil {
		return nil
	}
	rc, err := cell.NewRelayCell(streamID, cell.RelayEnd, []byte{cell.EndReasonExitPolicy})
	if err != nil {
		return err
	}
	circ.mu.Lock()
	defer circ.mu.Unlock()
	enc, err := circ.crypto.originateRelay(rc)
	if err != nil {
		return err
	}
	out := &cell.Cell{CircID: circ.CircuitID, Command: cell.CmdRelay, Payload: enc}
	return out.Encode(clientConn)
}

// handleTruncate handles RELAY_TRUNCATE cells per tor-spec.txt §5.5
// 只拆除本电路在下一跳的映射，不关闭共享出站 OR 连接。
func (h *ForwardingHandler) handleTruncate(circuitID uint32) error {
	h.logger.Info("Received RELAY_TRUNCATE", "circuit_id", circuitID)

	h.extendedMu.Lock()
	ext, exists := h.extended[circuitID]
	if exists {
		delete(h.extended, circuitID)
	}
	h.extendedMu.Unlock()

	if !exists {
		return nil
	}
	destroyCell := &cell.Cell{
		CircID:  ext.NextHopCircuitID,
		Command: cell.CmdDestroy,
		Payload: []byte{cell.DestroyReasonDestroyed},
	}
	if err := ext.sendToNextHop(destroyCell); err != nil {
		h.logger.Debug("truncate: DESTROY to next hop failed", "error", err)
	}
	h.logger.Info("Truncated extended circuit",
		"circuit_id", circuitID,
		"next_hop_circuit_id", ext.NextHopCircuitID)
	return nil
}

// HandleDestroy handles DESTROY cells and cleans up extended circuits
// 发送 DESTROY 到下一跳电路，但不关闭池化 OR 连接。
func (h *ForwardingHandler) HandleDestroy(circuitID uint32) error {
	h.logger.Info("Handling DESTROY", "circuit_id", circuitID)

	h.extendedMu.Lock()
	ext, exists := h.extended[circuitID]
	if exists {
		delete(h.extended, circuitID)
	}
	h.extendedMu.Unlock()

	if !exists {
		return nil
	}
	destroyCell := &cell.Cell{
		CircID:  ext.NextHopCircuitID,
		Command: cell.CmdDestroy,
		Payload: []byte{cell.DestroyReasonDestroyed},
	}
	if err := ext.sendToNextHop(destroyCell); err != nil {
		h.logger.Debug("destroy: DESTROY to next hop failed", "error", err)
	}
	h.logger.Info("Destroyed extended circuit",
		"circuit_id", circuitID,
		"next_hop_circuit_id", ext.NextHopCircuitID)
	return nil
}

// GetExtendedCircuitCount returns the number of extended circuits
func (h *ForwardingHandler) GetExtendedCircuitCount() int {
	h.extendedMu.RLock()
	defer h.extendedMu.RUnlock()
	return len(h.extended)
}

// CloseAll closes all extended circuits（不关闭池化出站连接，由 ExtensionHandler.Close 负责）。
func (h *ForwardingHandler) CloseAll() {
	h.extendedMu.Lock()
	defer h.extendedMu.Unlock()

	for circID, ext := range h.extended {
		destroyCell := &cell.Cell{
			CircID:  ext.NextHopCircuitID,
			Command: cell.CmdDestroy,
			Payload: []byte{cell.DestroyReasonDestroyed},
		}
		_ = ext.sendToNextHop(destroyCell)
		h.logger.Debug("Closed extended circuit", "circuit_id", circID)
	}
	h.extended = make(map[uint32]*ExtendedCircuit)
	h.hsMu.Lock()
	h.introByAuth = make(map[string]*hsRoleSlot)
	h.rendByCookie = make(map[string]*hsRoleSlot)
	h.hsMu.Unlock()
	h.logger.Info("Closed all extended circuits")
}
