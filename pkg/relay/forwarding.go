// Package relay - Cell forwarding for relay servers
// This file implements relay cell forwarding per tor-spec.txt §5.5-5.6
package relay

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// ExtendedCircuit tracks a circuit that has been extended to next hop
type ExtendedCircuit struct {
	ClientCircuitID  uint32 // Circuit ID on client side
	NextHopCircuitID uint32 // Circuit ID on next hop side
	NextHopAddress   string // Address of next hop
	NextHopConn      net.Conn
	RelayEarlyCount  int // Count of RELAY_EARLY cells forwarded
	mu               sync.Mutex
}

// ForwardingHandler manages cell forwarding between circuits
type ForwardingHandler struct {
	circuits   *CircuitHandler
	extended   map[uint32]*ExtendedCircuit // Map from client circuit ID to extended circuit
	extendedMu sync.RWMutex
	logger     *logger.Logger
}

// NewForwardingHandler creates a new forwarding handler
func NewForwardingHandler(circuits *CircuitHandler, log *logger.Logger) *ForwardingHandler {
	if log == nil {
		log = logger.NewDefault()
	}
	return &ForwardingHandler{
		circuits: circuits,
		extended: make(map[uint32]*ExtendedCircuit),
		logger:   log.Component("forwarding"),
	}
}

// RegisterExtendedCircuit registers an extended circuit for forwarding
func (h *ForwardingHandler) RegisterExtendedCircuit(clientCircID, nextHopCircID uint32, nextHopAddr string, nextHopConn net.Conn) error {
	h.extendedMu.Lock()
	defer h.extendedMu.Unlock()

	if _, exists := h.extended[clientCircID]; exists {
		return fmt.Errorf("circuit %d already extended", clientCircID)
	}

	h.extended[clientCircID] = &ExtendedCircuit{
		ClientCircuitID:  clientCircID,
		NextHopCircuitID: nextHopCircID,
		NextHopAddress:   nextHopAddr,
		NextHopConn:      nextHopConn,
		RelayEarlyCount:  0,
	}

	h.logger.Info("Registered extended circuit",
		"client_circuit_id", clientCircID,
		"next_hop_circuit_id", nextHopCircID,
		"next_hop_address", nextHopAddr)

	return nil
}

// ForwardRelayCell forwards a relay cell from client to next hop
// Per tor-spec.txt §5.5:
// - RELAY_EARLY cells are limited to 8 per circuit direction
// - After 8 RELAY_EARLY cells, convert to RELAY cells
// - Track counts to prevent circuit extension attacks
func (h *ForwardingHandler) ForwardRelayCell(ctx context.Context, fromClient bool, circuitID uint32, c *cell.Cell, clientConn net.Conn) error {
	// Check if this is an extended circuit
	h.extendedMu.RLock()
	ext, isExtended := h.extended[circuitID]
	h.extendedMu.RUnlock()

	if !isExtended {
		return h.handleLocalRelayCell(ctx, circuitID, c, clientConn)
	}

	// Forward to next hop
	if fromClient {
		return h.forwardToNextHop(ext, c)
	}
	return h.forwardToClient(ext, c)
}

// forwardToNextHop forwards a cell from client to next hop
func (h *ForwardingHandler) forwardToNextHop(ext *ExtendedCircuit, c *cell.Cell) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()

	// Handle RELAY_EARLY cell counting (tor-spec.txt §5.5)
	if c.Command == cell.CmdRelayEarly {
		if ext.RelayEarlyCount >= 8 {
			// Convert to RELAY cell after 8 RELAY_EARLY cells
			h.logger.Debug("Converting RELAY_EARLY to RELAY",
				"circuit_id", ext.ClientCircuitID,
				"count", ext.RelayEarlyCount)
			c.Command = cell.CmdRelay
		} else {
			ext.RelayEarlyCount++
			h.logger.Debug("Forwarding RELAY_EARLY",
				"circuit_id", ext.ClientCircuitID,
				"count", ext.RelayEarlyCount)
		}
	}

	// Create forwarded cell with next hop circuit ID
	forwardedCell := &cell.Cell{
		CircID:  ext.NextHopCircuitID,
		Command: c.Command,
		Payload: c.Payload,
	}

	// Send to next hop
	if err := forwardedCell.Encode(ext.NextHopConn); err != nil {
		h.logger.Error("Failed to forward cell to next hop",
			"circuit_id", ext.ClientCircuitID,
			"error", err)
		return fmt.Errorf("forward to next hop failed: %w", err)
	}

	h.logger.Debug("Forwarded cell to next hop",
		"client_circuit_id", ext.ClientCircuitID,
		"next_hop_circuit_id", ext.NextHopCircuitID,
		"command", c.Command)

	return nil
}

// forwardToClient forwards a cell from next hop to client
func (h *ForwardingHandler) forwardToClient(ext *ExtendedCircuit, c *cell.Cell) error {
	// This would be called when receiving cells from next hop
	// For now, this is a placeholder as we need connection tracking
	h.logger.Debug("Forwarding cell to client",
		"circuit_id", ext.ClientCircuitID,
		"command", c.Command)
	return nil
}

// handleLocalRelayCell handles relay cells for circuits that end at this relay
func (h *ForwardingHandler) handleLocalRelayCell(ctx context.Context, circuitID uint32, c *cell.Cell, clientConn net.Conn) error {
	circ, ok := h.circuits.GetCircuit(circuitID)
	if !ok || circ == nil || circ.crypto == nil {
		return fmt.Errorf("circuit %d crypto unavailable", circuitID)
	}
	plain, err := circ.crypto.decryptInbound(c.Payload)
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
		h.circuits.exits.NoteFwdDigest(circuitID, circ.crypto.FwdDigestSum())
	}
	relayCell, err := cell.DecodeRelayCell(plain)
	if err != nil {
		return fmt.Errorf("invalid relay cell: %w", err)
	}

	h.logger.Debug("Handling local relay cell",
		"circuit_id", circuitID,
		"command", cell.RelayCmdString(relayCell.Command),
		"stream_id", relayCell.StreamID)

	switch relayCell.Command {
	case cell.RelayBegin:
		if h.circuits.exits == nil {
			return h.rejectExitAttempt(circ, clientConn, relayCell.StreamID)
		}
		return h.circuits.exits.HandleBegin(ctx, circ, clientConn, relayCell.StreamID, relayCell.Data)

	case cell.RelayBeginDir:
		return h.rejectExitAttempt(circ, clientConn, relayCell.StreamID)

	case cell.RelayData:
		if h.circuits.exits != nil {
			return h.circuits.exits.HandleData(circ, clientConn, relayCell.StreamID, relayCell.Data)
		}
		return nil

	case cell.RelaySendme:
		if h.circuits.exits != nil {
			h.circuits.exits.HandleSendme(circuitID, relayCell.StreamID)
		}
		return nil

	case cell.RelayEnd:
		if h.circuits.exits != nil {
			h.circuits.exits.HandleEnd(circuitID, relayCell.StreamID)
		}
		return nil

	case cell.RelayExtend2:
		h.logger.Debug("RELAY_EXTEND2 on local circuit - extension path separate")
		return nil

	case cell.RelayTruncate:
		return h.handleTruncate(circuitID)

	default:
		return nil
	}
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
	plain, err := rc.Encode()
	if err != nil {
		return err
	}
	if len(plain) < 509 {
		pad := make([]byte, 509)
		copy(pad, plain)
		plain = pad
	}
	circ.mu.Lock()
	defer circ.mu.Unlock()
	enc, err := circ.crypto.encryptOutbound(plain[:509])
	if err != nil {
		return err
	}
	out := &cell.Cell{CircID: circ.CircuitID, Command: cell.CmdRelay, Payload: enc}
	return out.Encode(clientConn)
}

// handleTruncate handles RELAY_TRUNCATE cells per tor-spec.txt §5.5
// Returns true if the circuit had an extension that was torn down
func (h *ForwardingHandler) handleTruncate(circuitID uint32) error {
	h.logger.Info("Received RELAY_TRUNCATE", "circuit_id", circuitID)

	// Remove extended circuit if it exists
	h.extendedMu.Lock()
	defer h.extendedMu.Unlock()

	if ext, exists := h.extended[circuitID]; exists {
		// Close connection to next hop
		if ext.NextHopConn != nil {
			ext.NextHopConn.Close()
		}
		delete(h.extended, circuitID)
		h.logger.Info("Truncated extended circuit",
			"circuit_id", circuitID,
			"next_hop_circuit_id", ext.NextHopCircuitID)

		// Note: RELAY_TRUNCATED response should be sent by the OR handler
		// that has access to the client connection. The truncation itself
		// is complete - we've torn down the extension to the next hop.
	}

	return nil
}

// HandleDestroy handles DESTROY cells and cleans up extended circuits
func (h *ForwardingHandler) HandleDestroy(circuitID uint32) error {
	h.logger.Info("Handling DESTROY", "circuit_id", circuitID)

	// Clean up extended circuit
	h.extendedMu.Lock()
	if ext, exists := h.extended[circuitID]; exists {
		// Send DESTROY to next hop
		if ext.NextHopConn != nil {
			destroyCell := &cell.Cell{
				CircID:  ext.NextHopCircuitID,
				Command: cell.CmdDestroy,
				Payload: []byte{cell.DestroyReasonDestroyed},
			}
			destroyCell.Encode(ext.NextHopConn)
			ext.NextHopConn.Close()
		}
		delete(h.extended, circuitID)
		h.logger.Info("Destroyed extended circuit",
			"circuit_id", circuitID,
			"next_hop_circuit_id", ext.NextHopCircuitID)
	}
	h.extendedMu.Unlock()

	return nil
}

// GetExtendedCircuitCount returns the number of extended circuits
func (h *ForwardingHandler) GetExtendedCircuitCount() int {
	h.extendedMu.RLock()
	defer h.extendedMu.RUnlock()
	return len(h.extended)
}

// CloseAll closes all extended circuits
func (h *ForwardingHandler) CloseAll() {
	h.extendedMu.Lock()
	defer h.extendedMu.Unlock()

	for circID, ext := range h.extended {
		if ext.NextHopConn != nil {
			ext.NextHopConn.Close()
		}
		h.logger.Debug("Closed extended circuit", "circuit_id", circID)
	}
	h.extended = make(map[uint32]*ExtendedCircuit)
	h.logger.Info("Closed all extended circuits")
}
