// Package relay - Server-side circuit handling
// This file implements CREATE2/CREATED2 handling for relay servers
// Following tor-spec.txt §4-5 (server-side)
package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// ServerCircuit represents a server-side circuit
type ServerCircuit struct {
	CircuitID    uint32
	Created      time.Time
	LastActivity time.Time
	KeyMaterial  []byte
	crypto       *circuitCrypto
	ctx          context.Context
	cancel       context.CancelFunc
	ccEnabled    bool   // ntor-v3 已回 CC_FIELD_RESPONSE
	sendmeInc    int    // FlowCtrl=2 时一般为 31
	circNonce    []byte // rend_circ_nonce，ESTABLISH_INTRO MAC
	introAuth    []byte // 已建立引言点的 AUTH_KEY（32 字节）
	rendCookie   []byte // ESTABLISH_RENDEZVOUS cookie（20 字节）
	mu           sync.RWMutex
}

// CircuitHandler manages server-side circuits for a relay
type CircuitHandler struct {
	keys      *RelayKeys
	circuits  map[uint32]*ServerCircuit
	mu        sync.RWMutex
	logger    *logger.Logger
	ctx       context.Context
	forwarder *ForwardingHandler
	extender  *ExtensionHandler
	policy    *ExitPolicy
	exits     *ExitStreamManager
}

// NewCircuitHandler creates a new circuit handler
func NewCircuitHandler(keys *RelayKeys, log *logger.Logger) *CircuitHandler {
	return NewCircuitHandlerWithPolicy(keys, NewExitPolicy(log), log)
}

// NewCircuitHandlerWithPolicy 带出口策略。
func NewCircuitHandlerWithPolicy(keys *RelayKeys, policy *ExitPolicy, log *logger.Logger) *CircuitHandler {
	if log == nil {
		log = logger.NewDefault()
	}
	if policy == nil {
		policy = NewExitPolicy(log)
	}
	h := &CircuitHandler{
		keys:     keys,
		circuits: make(map[uint32]*ServerCircuit),
		logger:   log.Component("circuit-handler"),
		ctx:      context.Background(),
		policy:   policy,
		exits:    NewExitStreamManager(policy, log),
	}
	h.forwarder = NewForwardingHandler(h, log)
	h.extender = NewExtensionHandler(keys, h, log)
	h.extender.SetForwarder(h.forwarder)
	return h
}

// HandleCellFromConnection processes cells from a client connection
// This handles CREATE2 cells for circuit creation and RELAY cells for forwarding
func (h *CircuitHandler) HandleCellFromConnection(conn net.Conn, c *cell.Cell) error {
	switch c.Command {
	case cell.CmdCreate2:
		return h.handleCreate2(conn, c)
	case cell.CmdRelay, cell.CmdRelayEarly:
		return h.handleRelay(conn, c)
	case cell.CmdDestroy:
		return h.handleDestroy(c)
	default:
		h.logger.Debug("Ignoring cell command", "command", c.Command)
		return nil
	}
}

// handleCreate2 processes a CREATE2 cell and sends CREATED2 response
// Per tor-spec.txt §5.1:
//
//	CREATE2 cell contains:
//	  HTYPE (2 bytes) - handshake type (0x0002 for ntor)
//	  HLEN  (2 bytes) - handshake data length
//	  HDATA (HLEN bytes) - handshake data
//
//	CREATED2 response contains:
//	  HLEN (2 bytes) - handshake response length
//	  HDATA (HLEN bytes) - handshake response
func (h *CircuitHandler) handleCreate2(conn net.Conn, c *cell.Cell) error {
	h.logger.Info("Received CREATE2",
		"circuit_id", c.CircID,
		"data_len", len(c.Payload))

	// Check if circuit already exists
	h.mu.RLock()
	_, exists := h.circuits[c.CircID]
	h.mu.RUnlock()

	if exists {
		h.logger.Warn("CREATE2 for existing circuit", "circuit_id", c.CircID)
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
	}

	// Parse CREATE2 payload
	if len(c.Payload) < 4 {
		h.logger.Warn("CREATE2 payload too short", "len", len(c.Payload))
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
	}

	htype := uint16(c.Payload[0])<<8 | uint16(c.Payload[1])
	hlen := uint16(c.Payload[2])<<8 | uint16(c.Payload[3])

	h.logger.Debug("CREATE2 handshake", "type", htype, "len", hlen)

	if len(c.Payload) < 4+int(hlen) {
		h.logger.Warn("CREATE2 payload incomplete", "expected", 4+hlen, "got", len(c.Payload))
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
	}
	handshakeData := c.Payload[4 : 4+hlen]

	var response, keyMaterial, circNonce []byte
	var err error
	switch htype {
	case 0x0002: // classic ntor
		if len(handshakeData) != 84 {
			h.logger.Warn("Invalid ntor handshake length", "len", len(handshakeData))
			return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
		}
		response, keyMaterial, circNonce, err = crypto.NtorServerHandshakeWithNonce(
			handshakeData,
			h.keys.NtorOnionKey,
			h.keys.RSANodeID(),
		)
	case 0x0003: // ntor-v3
		if len(handshakeData) < crypto.NtorV3FixedClientLen {
			h.logger.Warn("Invalid ntor-v3 handshake length", "len", len(handshakeData))
			return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
		}
		sm := crypto.EncodeNtorV3Extensions([]crypto.NtorV3Extension{
			{Type: crypto.NtorV3ExtCCResponse, Data: []byte{31}},
		})
		response, keyMaterial, circNonce, err = crypto.NtorV3ServerHandshakeWithNonce(
			handshakeData,
			h.keys.Ed25519Public,
			h.keys.NtorOnionKey,
			crypto.NtorV3CircuitVerification,
			sm,
		)
	default:
		h.logger.Warn("Unsupported handshake type", "type", htype)
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
	}
	if err != nil {
		h.logger.Error("Handshake failed", "type", htype, "error", err)
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonInternal)
	}

	// Create circuit state
	cc, cerr := newCircuitCrypto(keyMaterial)
	if cerr != nil {
		h.logger.Error("circuit crypto init failed", "error", cerr)
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonInternal)
	}
	cctx, ccancel := context.WithCancel(h.ctx)
	ccOn := htype == 0x0003
	inc := 0
	if ccOn {
		inc = 31
	}
	circuit := &ServerCircuit{
		CircuitID:    c.CircID,
		Created:      time.Now(),
		LastActivity: time.Now(),
		KeyMaterial:  keyMaterial,
		crypto:       cc,
		ctx:          cctx,
		cancel:       ccancel,
		ccEnabled:    ccOn,
		sendmeInc:    inc,
		circNonce:    append([]byte(nil), circNonce...),
	}

	// Store circuit
	h.mu.Lock()
	h.circuits[c.CircID] = circuit
	h.mu.Unlock()
	if h.exits != nil && ccOn {
		h.exits.NoteCircuitFlow(c.CircID, true, inc)
	}

	h.logger.Info("Circuit created",
		"circuit_id", c.CircID,
		"handshake", htype,
		"key_material_len", len(keyMaterial))

	// Send CREATED2 response
	return h.sendCreated2(conn, c.CircID, response)
}

// sendCreated2 sends a CREATED2 cell with handshake response
func (h *CircuitHandler) sendCreated2(conn net.Conn, circuitID uint32, response []byte) error {
	// Build CREATED2 payload: HLEN (2) || HDATA (response)
	payload := make([]byte, 2+len(response))
	payload[0] = byte(len(response) >> 8)
	payload[1] = byte(len(response) & 0xff)
	copy(payload[2:], response)

	// Create CREATED2 cell
	created2 := &cell.Cell{
		CircID:  circuitID,
		Command: cell.CmdCreated2,
		Payload: payload,
	}

	// Encode and send
	if err := created2.Encode(conn); err != nil {
		return fmt.Errorf("failed to encode CREATED2: %w", err)
	}

	h.logger.Debug("Sent CREATED2",
		"circuit_id", circuitID,
		"response_len", len(response))

	return nil
}

// handleRelay processes RELAY and RELAY_EARLY cells
// Per tor-spec.txt §5.5-5.6, relay cells are forwarded to the next hop
// or handled locally if this is the end of the circuit
func (h *CircuitHandler) handleRelay(conn net.Conn, c *cell.Cell) error {
	h.mu.RLock()
	circuit, exists := h.circuits[c.CircID]
	h.mu.RUnlock()

	if !exists {
		h.logger.Warn("RELAY cell for unknown circuit", "circuit_id", c.CircID)
		return h.sendDestroyCell(conn, c.CircID, cell.DestroyReasonProtocol)
	}

	// Update activity timestamp
	circuit.mu.Lock()
	circuit.LastActivity = time.Now()
	circuit.mu.Unlock()

	h.logger.Debug("Received RELAY cell", "circuit_id", c.CircID, "command", c.Command)

	// Forward relay cell using ForwardingHandler
	// fromClient=true indicates this cell is from the client
	if err := h.forwarder.ForwardRelayCell(h.ctx, true, c.CircID, c, conn); err != nil {
		h.logger.Error("Failed to forward RELAY cell",
			"circuit_id", c.CircID,
			"error", err)
		return err
	}

	return nil
}

// handleDestroy processes DESTROY cells
func (h *CircuitHandler) handleDestroy(c *cell.Cell) error {
	h.logger.Info("Received DESTROY", "circuit_id", c.CircID)
	h.CloseCircuit(c.CircID)
	return nil
}

// sendDestroyCell sends a DESTROY cell with specified reason
func (h *CircuitHandler) sendDestroyCell(conn net.Conn, circuitID uint32, reason byte) error {
	destroy := &cell.Cell{
		CircID:  circuitID,
		Command: cell.CmdDestroy,
		Payload: []byte{reason},
	}

	if err := destroy.Encode(conn); err != nil {
		return fmt.Errorf("failed to encode DESTROY: %w", err)
	}

	h.logger.Debug("Sent DESTROY", "circuit_id", circuitID, "reason", reason)
	return nil
}

// GetCircuit retrieves a circuit by ID
func (h *CircuitHandler) GetCircuit(circuitID uint32) (*ServerCircuit, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	circuit, exists := h.circuits[circuitID]
	return circuit, exists
}

// GetCircuitCount returns the number of active circuits
func (h *CircuitHandler) GetCircuitCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.circuits)
}

// CloseCircuit destroys a circuit
func (h *CircuitHandler) CloseCircuit(circuitID uint32) {
	h.mu.Lock()
	circ := h.circuits[circuitID]
	delete(h.circuits, circuitID)
	h.mu.Unlock()
	if circ != nil && circ.cancel != nil {
		circ.cancel()
	}
	if h.exits != nil {
		h.exits.CloseCircuit(circuitID)
	}
	if h.forwarder != nil {
		_ = h.forwarder.HandleDestroy(circuitID)
	}
	h.logger.Info("Circuit closed", "circuit_id", circuitID)
}

// CloseAll destroys all circuits
func (h *CircuitHandler) CloseAll() {
	h.mu.Lock()
	all := make([]*ServerCircuit, 0, len(h.circuits))
	for _, c := range h.circuits {
		all = append(all, c)
	}
	count := len(h.circuits)
	h.circuits = make(map[uint32]*ServerCircuit)
	h.mu.Unlock()
	for _, c := range all {
		if c.cancel != nil {
			c.cancel()
		}
	}
	if h.forwarder != nil {
		h.forwarder.CloseAll()
	}
	if h.extender != nil {
		_ = h.extender.Close()
	}
	if h.exits != nil {
		h.exits.CloseAll()
	}
	h.logger.Info("All circuits closed", "count", count)
}

// GetForwardingHandler returns the forwarding handler for extension operations
func (h *CircuitHandler) GetForwardingHandler() *ForwardingHandler {
	return h.forwarder
}
