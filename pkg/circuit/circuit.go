// Package circuit provides circuit management for the Tor protocol.
// Circuits are paths through the Tor network used to route traffic.
package circuit

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 - SHA-1 required by Tor protocol (tor-spec.txt §6.1)
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

// State represents the current state of a circuit
type State int

const (
	// StateBuilding indicates the circuit is being built
	StateBuilding State = iota
	// StateOpen indicates the circuit is ready for use
	StateOpen
	// StateClosed indicates the circuit has been closed
	StateClosed
	// StateFailed indicates the circuit failed to build or operate
	StateFailed
)

// String returns a string representation of the state
func (s State) String() string {
	switch s {
	case StateBuilding:
		return "BUILDING"
	case StateOpen:
		return "OPEN"
	case StateClosed:
		return "CLOSED"
	case StateFailed:
		return "FAILED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// Circuit represents a Tor circuit
type Circuit struct {
	ID               uint32
	State            State
	CreatedAt        time.Time
	Hops             []*Hop
	IsolationKey     *IsolationKey // Isolation key for circuit isolation
	conn             interface{}   // Connection to the entry guard (interface{} to avoid circular import)
	mu               sync.RWMutex
	paddingEnabled   bool          // SPEC-002: Enable/disable circuit padding
	paddingInterval  time.Duration // SPEC-002: Interval for padding cells
	lastPaddingTime  time.Time     // SPEC-002: Last time a padding cell was sent
	lastActivityTime time.Time     // SPEC-002: Last time any cell was sent/received
	// CRYPTO-001: Running digests for relay cell verification per tor-spec.txt §6.1
	forwardDigest  hash.Hash // Client → Exit direction
	backwardDigest hash.Hash // Exit → Client direction
	// Stream protocol support
	relayReceiveChan chan *cell.RelayCell // Channel for receiving relay cells
	streamManager    interface{}          // Stream manager (interface{} to avoid circular import)
	nextStreamID     uint16               // 本电路下一个可用 StreamID（跳过 0）
	usedStreamIDs    map[uint16]struct{}  // 已占用的 StreamID（BEGIN 与 RESOLVE 共用）
	// Flow control per tor-spec.txt §7.4 / proposal 324
	packageWindow  int             // 还能发多少 DATA（经典窗口，或 Vegas 的 cwnd-inflight）
	deliverWindow  int             // Circuit-level deliver window (cells we can receive)
	sendmeInc      int             // FlowCtrl=2 的 sendme_inc；0 表示经典窗口 100
	sendmeReceived int             // Count of DATA cells received (for sending SENDME)
	sendmeSent     int             // Count of SENDME cells sent
	sendmeExpected []sendmePending // 发出 DATA 时记下的 v1 digest + 时间，供 SENDME / RTT
	ccParams       CCParams        // 共识 CC 参数；EnableCongestionControl 时启用 Vegas
	vegas          *vegasState     // 非 nil 表示本电路已协商 FlowCtrl=2
	// SECURITY-001: Replay protection per tor-spec.txt
	replayProtection *cell.ReplayProtection // Replay protection for cells
	// AUDIT-MED-4 FIX: Reusable timer to avoid GC pressure from time.After
	deliverTimer   *time.Timer // Timer for relay cell delivery timeout
	deliverTimerMu sync.Mutex
	mux            *CellMux
	destroyCh      chan struct{}
	destroyOnce    sync.Once
	destroyReason  byte
	conflux        *ConfluxSet   // 非 nil 表示本电路正在或已经参与 Conflux 套
	sendWake       chan struct{} // SENDME / 拆路时叫醒等窗的发送方
	exitFilter     ExitFilter    // Exit 的 p / p6 / 完整策略；IPv6 字面量必须检查
	circpad        *CircpadController // Padding=2 HS setup 机（可选）
}

// Hop represents a single hop in a circuit (one relay)
type Hop struct {
	Fingerprint string // Router fingerprint
	Address     string // Router address (IP:port)
	IsGuard     bool   // Whether this is a guard node
	IsExit      bool   // Whether this is an exit node

	// Cryptographic state for this hop (per tor-spec.txt §5.2)
	// These are derived from the key material during circuit extension
	ForwardCipher  cipher.Stream // AES-CTR cipher for encrypting cells (client→relay)
	BackwardCipher cipher.Stream // AES-CTR cipher for decrypting cells (relay→client)
	ForwardDigest  hash.Hash     // SHA-1 running digest for forward direction
	BackwardDigest hash.Hash     // SHA-1 running digest for backward direction
	CGO            *crypto.CGOPair
}

// NewHop creates a new hop with the given parameters
func NewHop(fingerprint, address string, isGuard, isExit bool) *Hop {
	return &Hop{
		Fingerprint: fingerprint,
		Address:     address,
		IsGuard:     isGuard,
		IsExit:      isExit,
	}
}

// SetCryptoState sets the cryptographic state for this hop
// This should be called after circuit extension when key material is derived
func (h *Hop) SetCryptoState(forwardCipher, backwardCipher cipher.Stream, forwardDigest, backwardDigest hash.Hash) {
	h.ForwardCipher = forwardCipher
	h.BackwardCipher = backwardCipher
	h.ForwardDigest = forwardDigest
	h.BackwardDigest = backwardDigest
}

// NewCircuit creates a new circuit with the given ID
func NewCircuit(id uint32) *Circuit {
	now := time.Now()
	deliverTimer := time.NewTimer(deliverRelayCellTimeout)
	stopAndDrainTimer(deliverTimer)

	return &Circuit{
		ID:               id,
		State:            StateBuilding,
		CreatedAt:        now,
		Hops:             make([]*Hop, 0, 3),             // Typical circuit has 3 hops
		IsolationKey:     nil,                            // No isolation by default (backward compatible)
		conn:             nil,                            // Connection set later
		paddingEnabled:   true,                           // SPEC-002: Enable padding by default
		paddingInterval:  5 * time.Second,                // SPEC-002: Default 5-second padding interval
		lastPaddingTime:  now,                            // SPEC-002: Initialize padding timer
		lastActivityTime: now,                            // SPEC-002: Initialize activity timer
		forwardDigest:    sha1.New(),                     // CRYPTO-001: Initialize forward digest
		backwardDigest:   sha1.New(),                     // CRYPTO-001: Initialize backward digest
		relayReceiveChan: make(chan *cell.RelayCell, 32), // Buffer for incoming relay cells
		streamManager:    nil,                            // Stream manager set later
		nextStreamID:     1,                              // spec：RESOLVE/BEGIN 都必须用非 0 StreamID
		usedStreamIDs:    make(map[uint16]struct{}),
		packageWindow:    1000, // tor-spec.txt §7.4: Initial circuit window is 1000
		deliverWindow:    1000, // tor-spec.txt §7.4: Initial circuit window is 1000
		sendmeReceived:   0,    // No DATA cells received yet
		sendmeSent:       0,    // No SENDME cells sent yet
		sendmeExpected:   nil,
		ccParams:         DefaultCCParams(),
		replayProtection: cell.NewReplayProtection(), // SECURITY-001: Initialize replay protection
		deliverTimer:     deliverTimer,               // AUDIT-MED-4 FIX: Reusable timer
		destroyCh:        make(chan struct{}),
		sendWake:         make(chan struct{}, 1),
	}
}

// NotifyDestroyed 由连接 mux 在收到 DESTROY 时调用，打断 RELAY 等待。
func (c *Circuit) NotifyDestroyed(reason byte) {
	if c == nil || c.destroyCh == nil {
		return
	}
	c.destroyOnce.Do(func() {
		c.mu.Lock()
		c.destroyReason = reason
		c.mu.Unlock()
		close(c.destroyCh)
	})
}

// AddHop adds a hop to the circuit
func (c *Circuit) AddHop(hop *Hop) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.State != StateBuilding {
		return fmt.Errorf("cannot add hop to circuit in state %s", c.State)
	}

	c.Hops = append(c.Hops, hop)
	return nil
}

// SetState sets the circuit state
func (c *Circuit) SetState(state State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.State = state
}

// GetState returns the current circuit state
func (c *Circuit) GetState() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.State
}

// GetID returns the circuit ID
func (c *Circuit) GetID() uint32 {
	return c.ID
}

// Length returns the number of hops in the circuit
func (c *Circuit) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Hops)
}

// IsReady returns true if the circuit is ready for use
func (c *Circuit) IsReady() bool {
	return c.GetState() == StateOpen
}

// Age returns how long the circuit has existed
func (c *Circuit) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

// GetHops returns a copy of the circuit hops slice.
// Note: While the slice itself is copied, the Hop pointers are shared.
// Callers should not modify the Hop objects directly.
func (c *Circuit) GetHops() []*Hop {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hops := make([]*Hop, len(c.Hops))
	copy(hops, c.Hops)
	return hops
}

// Close closes the circuit and sets its state to closed.
// This is safe to call multiple times.
func (c *Circuit) Close() {
	c.mu.Lock()
	if c.State == StateClosed {
		c.mu.Unlock()
		return
	}
	c.State = StateClosed
	set := c.conflux
	c.conflux = nil
	mux := c.mux
	c.mux = nil
	conn := c.conn
	if c.relayReceiveChan != nil {
		close(c.relayReceiveChan)
		c.relayReceiveChan = nil
	}
	c.mu.Unlock()

	c.NotifyDestroyed(0)
	c.wakeSenders()

	if set != nil {
		set.onLegClosed(c)
	}

	if mux != nil {
		mux.Close()
	} else if closer, ok := conn.(interface{ Close() error }); ok && conn != nil {
		_ = closer.Close()
	}

	c.deliverTimerMu.Lock()
	defer c.deliverTimerMu.Unlock()
	if c.deliverTimer != nil {
		stopAndDrainTimer(c.deliverTimer)
	}
}

// Manager manages a collection of circuits
type Manager struct {
	circuits map[uint32]*Circuit
	nextID   uint32
	mu       sync.RWMutex
	closed   bool
}

// NewManager creates a new circuit manager
func NewManager() *Manager {
	return &Manager{
		circuits: make(map[uint32]*Circuit),
		nextID:   newClientCircID(), // link proto ≥4：发起方 CircID MSB 必须为 1
	}
}

// newClientCircID 从高半区随机选一个非 0 CircID。
// tor-spec create-created-cells：link protocol v4+ 发起方 MUST set MSB to 1。
func newClientCircID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0x80000001
	}
	id := binary.BigEndian.Uint32(b[:]) | 0x80000000
	if id == 0x80000000 {
		return 0x80000001
	}
	return id
}

// CreateCircuit creates a new circuit and returns its ID
func (m *Manager) CreateCircuit() (*Circuit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("manager is closed")
	}

	id := m.nextID
	for {
		if _, exists := m.circuits[id]; !exists && id != 0 {
			break
		}
		id = newClientCircID()
		if id == m.nextID {
			return nil, fmt.Errorf("no available circuit IDs")
		}
	}
	m.nextID = newClientCircID()

	circuit := NewCircuit(id)
	m.circuits[id] = circuit
	return circuit, nil
}

// GetCircuit returns a circuit by ID
func (m *Manager) GetCircuit(id uint32) (*Circuit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	circuit, exists := m.circuits[id]
	if !exists {
		return nil, fmt.Errorf("circuit %d not found", id)
	}
	return circuit, nil
}

// CloseCircuit closes a circuit
func (m *Manager) CloseCircuit(id uint32) error {
	m.mu.Lock()
	circuit, exists := m.circuits[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("circuit %d not found", id)
	}
	delete(m.circuits, id)
	m.mu.Unlock()
	// 必须走 Circuit.Close，才能拆掉 Conflux 另一条腿并释放连接。
	circuit.Close()
	m.sweepClosed()
	return nil
}

// sweepClosed 清掉已被对腿 Close 带下来、但仍留在 map 里的电路。
func (m *Manager) sweepClosed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, circ := range m.circuits {
		if circ.GetState() == StateClosed {
			delete(m.circuits, id)
		}
	}
}

// ListCircuits returns a list of all circuit IDs
func (m *Manager) ListCircuits() []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]uint32, 0, len(m.circuits))
	for id := range m.circuits {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active circuits
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.circuits)
}

// Close closes all circuits and shuts down the manager gracefully
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("manager already closed")
	}

	// Mark as closed to prevent new circuits
	m.closed = true

	circuits := make([]*Circuit, 0, len(m.circuits))
	for id, circ := range m.circuits {
		circuits = append(circuits, circ)
		delete(m.circuits, id)
	}
	m.mu.Unlock()
	for _, circ := range circuits {
		circ.Close()
	}
	m.mu.Lock()

	return nil
}

// IsClosed returns true if the manager has been closed
func (m *Manager) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// SPEC-002: Circuit padding configuration and control
// These methods provide infrastructure for enhanced circuit padding per padding-spec.txt
// Current implementation provides basic padding support with hooks for future adaptive padding

// SetPaddingEnabled enables or disables circuit padding (SPEC-002)
// When enabled, circuits will send PADDING cells according to padding policy
func (c *Circuit) SetPaddingEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paddingEnabled = enabled
}

// IsPaddingEnabled returns whether padding is enabled for this circuit (SPEC-002)
func (c *Circuit) IsPaddingEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.paddingEnabled
}

// SetPaddingInterval sets the interval for padding cells (SPEC-002)
// interval: time between padding cells (0 = adaptive/traffic-based)
// This provides infrastructure for implementing adaptive padding per padding-spec.txt
func (c *Circuit) SetPaddingInterval(interval time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paddingInterval = interval
}

// GetPaddingInterval returns the current padding interval (SPEC-002)
func (c *Circuit) GetPaddingInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.paddingInterval
}

// ShouldSendPadding determines if a padding cell should be sent (SPEC-002)
// Implements basic time-based padding to improve traffic analysis resistance
// per tor-spec.txt §7.1 and padding-spec.txt
//
// Basic policy: Send padding if:
// 1. Padding is enabled
// 2. Circuit is open
// 3. paddingInterval has elapsed since last padding cell
// 4. No recent activity (prevents redundant padding during active use)
func (c *Circuit) ShouldSendPadding() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Basic policy: padding enabled and circuit is open
	if !c.paddingEnabled || c.State != StateOpen {
		return false
	}

	// If no interval configured (0), padding is disabled
	if c.paddingInterval == 0 {
		return false
	}

	now := time.Now()

	// Check if padding interval has elapsed since last padding
	timeSinceLastPadding := now.Sub(c.lastPaddingTime)
	if timeSinceLastPadding < c.paddingInterval {
		return false
	}

	// Don't send padding if there's been recent activity (within 80% of padding interval)
	// This prevents redundant padding when circuit is actively used
	activityThreshold := time.Duration(float64(c.paddingInterval) * 0.8)
	timeSinceActivity := now.Sub(c.lastActivityTime)
	if timeSinceActivity < activityThreshold {
		return false
	}

	return true
}

// RecordPaddingSent updates the last padding time (SPEC-002)
// Should be called after successfully sending a padding cell
func (c *Circuit) RecordPaddingSent() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastPaddingTime = time.Now()
}

// RecordActivity updates the last activity time (SPEC-002)
// Should be called when sending or receiving non-padding cells
func (c *Circuit) RecordActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastActivityTime = time.Now()
}

// Direction represents the direction of relay cell flow
type Direction int

const (
	// DirectionForward is client → exit
	DirectionForward Direction = iota
	// DirectionBackward is exit → client
	DirectionBackward
)

// CRYPTO-001: Relay cell digest verification per tor-spec.txt §6.1
// "Each RELAY cell includes a running digest field computed over all relay cells
// sent in same direction on the circuit."

// UpdateDigest updates the running digest for relay cells (CRYPTO-001)
// This must be called for every relay cell sent or received to maintain digest state.
// The digest is computed over the entire relay cell with the digest field zeroed.
// Per tor-spec.txt §6.1: digest = SHA1(digest | relay_cell_with_zeroed_digest)
func (c *Circuit) UpdateDigest(direction Direction, cellData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(cellData) < 11 {
		return fmt.Errorf("relay cell data too short: %d < 11", len(cellData))
	}

	// Create a copy with digest field zeroed (bytes 5-8)
	cellCopy := make([]byte, len(cellData))
	copy(cellCopy, cellData)
	cellCopy[5] = 0
	cellCopy[6] = 0
	cellCopy[7] = 0
	cellCopy[8] = 0

	// Update appropriate digest
	var digest hash.Hash
	if direction == DirectionForward {
		digest = c.forwardDigest
	} else {
		digest = c.backwardDigest
	}

	if digest == nil {
		return fmt.Errorf("digest not initialized for direction %d", direction)
	}

	_, err := digest.Write(cellCopy)
	return err
}

// VerifyDigest verifies the digest of an incoming relay cell (CRYPTO-001)
// Per tor-spec.txt §6.1, the digest is computed over the cell with the digest field zeroed.
// This function must clone the hash state to verify without modifying it.
// Note: This is a public API but is primarily used for testing. For production relay cell verification,
// use verifyRelayCellDigest which properly integrates with circuit state updates.
func (c *Circuit) VerifyDigest(direction Direction, cellData []byte, receivedDigest [4]byte) error {
	if len(cellData) < 11 {
		return fmt.Errorf("relay cell too short for digest verification: %d < 11", len(cellData))
	}

	c.mu.RLock()
	var digest hash.Hash
	if direction == DirectionForward {
		digest = c.forwardDigest
	} else {
		digest = c.backwardDigest
	}

	if digest == nil {
		c.mu.RUnlock()
		return fmt.Errorf("digest not initialized for direction %d", direction)
	}

	// Clone the hash state while holding the read lock to prevent races with UpdateDigest
	hashClone, err := crypto.CloneHash(digest)
	c.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to clone hash state for verification: %w", err)
	}

	// Create a copy with digest zeroed for verification
	cellCopy := make([]byte, len(cellData))
	copy(cellCopy, cellData)
	cellCopy[5] = 0
	cellCopy[6] = 0
	cellCopy[7] = 0
	cellCopy[8] = 0

	// Write the cell to the cloned hash state
	if _, err := hashClone.Write(cellCopy); err != nil {
		return fmt.Errorf("failed to update hash for verification: %w", err)
	}

	// Compute expected digest (first 4 bytes of hash)
	expectedSum := hashClone.Sum(nil)
	expected := [4]byte{expectedSum[0], expectedSum[1], expectedSum[2], expectedSum[3]}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(expected[:], receivedDigest[:]) != 1 {
		return fmt.Errorf("relay cell digest verification failed: expected %x, got %x", expected, receivedDigest)
	}

	return nil
}

// ResetDigests resets the running digests (CRYPTO-001)
// This should be called when establishing a new circuit or after certain protocol events.
func (c *Circuit) ResetDigests() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forwardDigest.Reset()
	c.backwardDigest.Reset()
}

// SetIsolationKey sets the isolation key for this circuit
func (c *Circuit) SetIsolationKey(key *IsolationKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.IsolationKey = key
}

// GetIsolationKey returns the isolation key for this circuit
func (c *Circuit) GetIsolationKey() *IsolationKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.IsolationKey
}

// SetConnection sets the underlying connection for this circuit
// conn should be a *connection.Connection, but we use interface{} to avoid circular imports
func (c *Circuit) SetConnection(conn interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
}

// SetMux 绑定连接级 cell 分发器，CREATE2/EXTEND2 通过它收响应。
func (c *Circuit) SetMux(mux *CellMux) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mux = mux
}

// SetStreamManager sets the stream manager for this circuit
// mgr should be a *stream.Manager, but we use interface{} to avoid circular imports
func (c *Circuit) SetStreamManager(mgr interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamManager = mgr
}

// AllocateStreamID 分配本电路上未占用的非 0 StreamID。
// RELAY_RESOLVE 与 RELAY_BEGIN 必须共用此分配器，否则会撞号。
// C Tor 对 RELAY_RESOLVE + stream_id==0 直接丢弃（bug 7889）。
func (c *Circuit) AllocateStreamID() (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.usedStreamIDs == nil {
		c.usedStreamIDs = make(map[uint16]struct{})
	}
	if c.nextStreamID == 0 {
		c.nextStreamID = 1
	}

	start := c.nextStreamID
	for {
		id := c.nextStreamID
		c.nextStreamID++
		if c.nextStreamID == 0 {
			c.nextStreamID = 1
		}
		if id == 0 {
			continue
		}
		if _, used := c.usedStreamIDs[id]; used {
			if c.nextStreamID == start {
				return 0, fmt.Errorf("no free stream IDs on circuit %d", c.ID)
			}
			continue
		}
		c.usedStreamIDs[id] = struct{}{}
		return id, nil
	}
}

// ReleaseStreamID 释放本电路上的 StreamID，供后续 BEGIN/RESOLVE 复用。
func (c *Circuit) ReleaseStreamID(id uint16) {
	if id == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.usedStreamIDs, id)
}

// encryptForward encrypts a relay cell payload with each hop's forward cipher
// This implements the onion encryption per tor-spec.txt §6.1
// Onion 加密从 hops 末尾向前：先 Exit、再 Middle、最后 Guard，使 Guard 层在最外。
func (c *Circuit) encryptForward(payload []byte) []byte {
	c.mu.RLock()
	hops := c.Hops
	c.mu.RUnlock()

	// Make a copy to avoid modifying the original
	encrypted := make([]byte, len(payload))
	copy(encrypted, payload)

	// Encrypt with each hop's cipher in reverse order (exit -> middle -> guard)
	// We apply layers from innermost (exit) to outermost (guard) so the guard's layer
	// is the outermost and will be decrypted first by the guard when it receives the cell
	for i := len(hops) - 1; i >= 0; i-- {
		hop := hops[i]
		if hop.ForwardCipher != nil {
			// XOR with the cipher stream (AES-CTR encryption)
			hop.ForwardCipher.XORKeyStream(encrypted, encrypted)
		}
	}

	return encrypted
}

// decryptBackward decrypts a relay cell payload from the circuit
// This implements the onion decryption per tor-spec.txt §6.1
// The payload is decrypted in REVERSE order (exit -> middle -> guard)
func (c *Circuit) decryptBackward(payload []byte) []byte {
	c.mu.RLock()
	hops := c.Hops
	c.mu.RUnlock()

	// Make a copy to avoid modifying the original
	decrypted := make([]byte, len(payload))
	copy(decrypted, payload)

	// Decrypt with each hop's cipher in reverse order (exit -> middle -> guard)
	// We receive the cell from the guard, which is the last to encrypt (first to decrypt)
	for _, hop := range hops {
		if hop.BackwardCipher != nil {
			// XOR with the cipher stream (AES-CTR decryption)
			hop.BackwardCipher.XORKeyStream(decrypted, decrypted)
		}
	}

	return decrypted
}

// updateHopDigests updates the per-hop running digests for a relay cell
// This is called after encryption/decryption to update each hop's digest state
func (c *Circuit) updateHopDigests(direction Direction, payload []byte) error {
	c.mu.RLock()
	hops := c.Hops
	c.mu.RUnlock()

	if len(payload) < 11 {
		return fmt.Errorf("relay cell data too short: %d < 11", len(payload))
	}

	// Create a copy with digest field zeroed (bytes 5-8)
	cellCopy := make([]byte, len(payload))
	copy(cellCopy, payload)
	cellCopy[5] = 0
	cellCopy[6] = 0
	cellCopy[7] = 0
	cellCopy[8] = 0

	// Update the appropriate digest for each hop
	if direction == DirectionForward {
		// Forward: update each hop's forward digest
		for _, hop := range hops {
			if hop.ForwardDigest != nil {
				if _, err := hop.ForwardDigest.Write(cellCopy); err != nil {
					return fmt.Errorf("failed to update forward digest for hop: %w", err)
				}
			}
		}
	} else {
		// Backward: update each hop's backward digest
		for _, hop := range hops {
			if hop.BackwardDigest != nil {
				if _, err := hop.BackwardDigest.Write(cellCopy); err != nil {
					return fmt.Errorf("failed to update backward digest for hop: %w", err)
				}
			}
		}
	}

	return nil
}

// verifyRelayCellDigest verifies the relay cell digest and returns the hop index that recognizes it.
// Per tor-spec.txt §6.1, relay cell digest is computed over the cell payload with the digest field zeroed,
// and each hop maintains a running hash of all cells it processes.
// Returns the hop index that recognized the cell, or -1 if unrecognized
func (c *Circuit) verifyRelayCellDigest(payload []byte) (int, error) {
	c.mu.RLock()
	hops := c.Hops
	c.mu.RUnlock()

	if len(payload) < 11 {
		return -1, fmt.Errorf("relay cell payload too short: %d < 11", len(payload))
	}

	// Extract the digest from the cell (bytes 5-8)
	var cellDigest [4]byte
	copy(cellDigest[:], payload[5:9])

	// Check if this cell is recognized by any hop
	// A cell is "recognized" if:
	// 1. The digest matches the expected post-cell digest (after writing the cell to the hash)
	// 2. The "recognized" field is zero (bytes 1-2)

	recognized := binary.BigEndian.Uint16(payload[1:3])

	// Create a copy with digest zeroed for digest computation
	cellCopy := make([]byte, len(payload))
	copy(cellCopy, payload)
	cellCopy[5] = 0
	cellCopy[6] = 0
	cellCopy[7] = 0
	cellCopy[8] = 0

	// Try each hop to see which one recognizes this cell
	for hopIdx, hop := range hops {
		if hop.BackwardDigest == nil {
			continue
		}

		// Clone the hash state to compute the expected digest without modifying the running digest
		hashClone, err := crypto.CloneHash(hop.BackwardDigest)
		if err != nil {
			return -1, fmt.Errorf("failed to clone hash state for hop %d: %w", hopIdx, err)
		}

		// Write the cell to the cloned hash state
		if _, err := hashClone.Write(cellCopy); err != nil {
			return -1, fmt.Errorf("failed to update hash for hop %d: %w", hopIdx, err)
		}

		// Get the digest from the cloned state
		expectedSum := hashClone.Sum(nil)
		expected := [4]byte{expectedSum[0], expectedSum[1], expectedSum[2], expectedSum[3]}

		// Check if digest matches AND recognized field is zero
		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare(expected[:], cellDigest[:]) == 1 && recognized == 0 {
			// This hop recognizes the cell
			// Now update the real (non-cloned) digest with this cell
			if _, err := hop.BackwardDigest.Write(cellCopy); err != nil {
				return -1, fmt.Errorf("failed to update backward digest: %w", err)
			}
			return hopIdx, nil
		}
	}

	// No hop recognized this cell - might be for a stream we don't have
	// or an error condition
	return -1, nil
}

// decrementPackageWindow decrements the circuit-level package window
// Returns an error if the window is exhausted
func (c *Circuit) decrementPackageWindow() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.vegas != nil {
		if c.vegas.inflight >= c.vegas.cwnd {
			return fmt.Errorf("%w: cannot send more cells until SENDME received", ErrWindowExhausted)
		}
		c.vegas.inflight++
		c.packageWindow = c.vegas.packageWindow()
		return nil
	}

	if c.packageWindow <= 0 {
		return fmt.Errorf("%w: cannot send more cells until SENDME received", ErrWindowExhausted)
	}

	c.packageWindow--
	return nil
}

// incrementPackageWindow increments the circuit-level package window
// This is called when we receive a SENDME cell
func (c *Circuit) incrementPackageWindow() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Per tor-spec.txt §7.4, each SENDME increments the window by 100
	c.packageWindow += 100
	c.wakeSenders()
}

// decrementDeliverWindow decrements the circuit-level deliver window
// Returns an error if the window is exhausted
func (c *Circuit) decrementDeliverWindow() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.deliverWindow <= 0 {
		return fmt.Errorf("deliver window exhausted: cannot receive more cells until SENDME sent")
	}

	c.deliverWindow--
	c.sendmeReceived++

	return nil
}

// shouldSendCircuitSendme checks if we should send a circuit-level SENDME
// Per tor-spec.txt §7.4, send SENDME every 100 cells received
func (c *Circuit) shouldSendCircuitSendme() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.sendmeReceived >= 100
}

// Stream-level flow control methods

// decrementStreamPackageWindow decrements the stream-level package window
func (c *Circuit) decrementStreamPackageWindow(streamID uint16) error {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()

	if mgr == nil {
		// No stream manager, skip stream-level flow control
		return nil
	}

	// Type assert to stream manager interface
	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return nil
	}

	streamIface, err := getter.GetStream(streamID)
	if err != nil {
		// Stream doesn't exist, skip flow control
		return nil
	}

	// Type assert to stream with flow control methods
	type flowControlStream interface {
		DecrementPackageWindow() error
	}
	stream, ok := streamIface.(flowControlStream)
	if !ok {
		return nil
	}

	return stream.DecrementPackageWindow()
}

// decrementStreamDeliverWindow decrements the stream-level deliver window
func (c *Circuit) decrementStreamDeliverWindow(streamID uint16) error {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()

	if mgr == nil {
		return nil
	}

	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return nil
	}

	streamIface, err := getter.GetStream(streamID)
	if err != nil {
		return nil
	}

	type flowControlStream interface {
		DecrementDeliverWindow() error
	}
	stream, ok := streamIface.(flowControlStream)
	if !ok {
		return nil
	}

	return stream.DecrementDeliverWindow()
}

// shouldSendStreamSendme checks if we should send a stream-level SENDME
func (c *Circuit) shouldSendStreamSendme(streamID uint16) bool {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()

	if mgr == nil {
		return false
	}

	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return false
	}

	streamIface, err := getter.GetStream(streamID)
	if err != nil {
		return false
	}

	type flowControlStream interface {
		ShouldSendStreamSendme() bool
	}
	stream, ok := streamIface.(flowControlStream)
	if !ok {
		return false
	}

	return stream.ShouldSendStreamSendme()
}

// sendStreamSendme sends a stream-level SENDME cell
func (c *Circuit) sendStreamSendme(streamID uint16) error {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()

	if mgr == nil {
		return fmt.Errorf("no stream manager")
	}

	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return fmt.Errorf("stream manager does not support GetStream")
	}

	streamIface, err := getter.GetStream(streamID)
	if err != nil {
		return fmt.Errorf("stream not found: %w", err)
	}

	type flowControlStream interface {
		RecordStreamSendmeSent()
	}
	stream, ok := streamIface.(flowControlStream)
	if !ok {
		return fmt.Errorf("stream does not support flow control")
	}

	// Record that we're sending a SENDME
	stream.RecordStreamSendmeSent()

	// Send SENDME cell with stream ID
	sendmeCell, err := cell.NewRelayCell(streamID, cell.RelaySendme, []byte{})
	if err != nil {
		return fmt.Errorf("failed to create stream SENDME cell: %w", err)
	}
	return c.SendRelayCell(sendmeCell)
}

// incrementStreamPackageWindow increments the stream-level package window
func (c *Circuit) incrementStreamPackageWindow(streamID uint16) {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()

	if mgr == nil {
		return
	}

	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return
	}

	streamIface, err := getter.GetStream(streamID)
	if err != nil {
		return
	}

	type flowControlStream interface {
		IncrementPackageWindow()
	}
	stream, ok := streamIface.(flowControlStream)
	if !ok {
		return
	}

	stream.IncrementPackageWindow()
	c.wakeSenders()
}

// deliverToStream delivers a relay cell to the appropriate stream via the stream manager
func (c *Circuit) deliverToStream(relayCell *cell.RelayCell) error {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()

	if mgr == nil {
		return fmt.Errorf("no stream manager configured")
	}

	// Type assert to stream manager interface
	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return fmt.Errorf("stream manager does not support GetStream")
	}

	streamIface, err := getter.GetStream(relayCell.StreamID)
	if err != nil {
		return fmt.Errorf("stream %d not found: %w", relayCell.StreamID, err)
	}

	// Type assert to stream with ReceiveData method
	type dataReceiver interface {
		ReceiveData([]byte) error
	}
	stream, ok := streamIface.(dataReceiver)
	if !ok {
		return fmt.Errorf("stream does not support ReceiveData")
	}

	// Handle different relay cell commands
	switch relayCell.Command {
	case cell.RelayData:
		// Deliver data to stream's receive queue
		return stream.ReceiveData(relayCell.Data)
	case cell.RelayEnd:
		// Signal stream closure by delivering EOF (empty data indicates END)
		return stream.ReceiveData(nil)
	default:
		// Other commands can be handled here if needed
		return nil
	}
}

// SendRelayCell sends a relay cell through the circuit
// This encrypts the relay cell with per-hop cryptography and sends it through the connection
func (c *Circuit) SendRelayCell(relayCell *cell.RelayCell) error {
	if relayCell != nil && cell.ConfluxShouldMultiplex(relayCell.Command) {
		if set := c.confluxSet(); set != nil && c.ConfluxLinked() {
			return set.sendMultiplexed(relayCell)
		}
	}
	return c.sendRelayCellLocal(relayCell)
}

// SendRelayCellToHop 将 relay cell 加密到指定跳（0=guard）后发出。
// Padding=2 HS setup 机协商目标为第二跳（hopIndex=1）。
func (c *Circuit) SendRelayCellToHop(relayCell *cell.RelayCell, hopIndex int) error {
	if relayCell == nil {
		return fmt.Errorf("relay cell is nil")
	}
	c.mu.RLock()
	conn := c.conn
	state := c.State
	nHops := len(c.Hops)
	c.mu.RUnlock()
	if state != StateOpen && state != StateBuilding {
		return fmt.Errorf("circuit not usable: state=%s", state)
	}
	if hopIndex < 0 || hopIndex >= nHops {
		return fmt.Errorf("hop index %d out of range [0,%d)", hopIndex, nHops)
	}
	if conn == nil {
		return fmt.Errorf("circuit has no connection")
	}

	c.mu.RLock()
	destCGO := c.Hops[hopIndex].usesCGO()
	c.mu.RUnlock()

	var payload []byte
	var err error
	if destCGO {
		payload, err = cell.EncodeRelayCellV1(relayCell)
		if err != nil {
			return fmt.Errorf("failed to encode v1 relay cell: %w", err)
		}
		end := cell.V1MessageEnd(payload)
		if end+4 < len(payload) {
			if _, err := rand.Read(payload[end+4:]); err != nil {
				return fmt.Errorf("failed to randomize v1 padding: %w", err)
			}
		}
	} else {
		payload, err = relayCell.Encode()
		if err != nil {
			return fmt.Errorf("failed to encode relay cell: %w", err)
		}
	}

	cmd := cell.CmdRelay
	encryptedPayload, _, err := c.encryptOnion(byte(cmd), hopIndex, payload)
	if err != nil {
		return fmt.Errorf("onion encrypt to hop %d: %w", hopIndex, err)
	}

	type cellSender interface {
		SendCell(*cell.Cell) error
	}
	sender, ok := conn.(cellSender)
	if !ok {
		return fmt.Errorf("connection does not support SendCell")
	}
	if err := sender.SendCell(&cell.Cell{CircID: c.ID, Command: cmd, Payload: encryptedPayload}); err != nil {
		return fmt.Errorf("failed to send cell: %w", err)
	}
	c.RecordActivity()
	return nil
}

// AttachCircpad 绑定 HS setup padding 控制器。
func (c *Circuit) AttachCircpad(ctrl *CircpadController) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.circpad = ctrl
	c.mu.Unlock()
}

// Circpad 返回已绑定的控制器（可能为 nil）。
func (c *Circuit) Circpad() *CircpadController {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.circpad
}

// StartHSSetupPadding 在共识允许且中间跳宣告 Padding=2 时启动客户端 HS setup 机，
// 并立即发出 PADDING_NEGOTIATE START 到第二跳。
func (c *Circuit) StartHSSetupPadding(kind HSSetupKind, middleSupportsPadding2 bool, cfg CircpadConfig) error {
	if cfg.Disabled {
		return fmt.Errorf("circpad disabled by consensus")
	}
	if !middleSupportsPadding2 {
		return fmt.Errorf("middle hop does not advertise Padding=2")
	}
	c.mu.RLock()
	nHops := len(c.Hops)
	c.mu.RUnlock()
	if nHops < 2 {
		return fmt.Errorf("need at least 2 hops for circpad setup machine")
	}
	ctrl := NewCircpadController(cfg)
	if err := ctrl.StartHSSetup(kind); err != nil {
		return err
	}
	rc, err := ctrl.BuildNegotiateStart()
	if err != nil {
		return err
	}
	// 目标跳 = TargetHop（1-based）→ 0-based index
	hopIdx := ctrl.TargetHop() - 1
	if err := c.SendRelayCellToHop(rc, hopIdx); err != nil {
		return fmt.Errorf("send PADDING_NEGOTIATE: %w", err)
	}
	ctrl.MarkNegotiateSent()
	c.AttachCircpad(ctrl)
	return nil
}

func (c *Circuit) destUsesCGO() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dest := len(c.Hops) - 1
	return dest >= 0 && c.Hops[dest].usesCGO()
}

func (c *Circuit) sendRelayCellLocal(relayCell *cell.RelayCell) error {
	recordSendme := false
	reserved := false
	if relayCell.Command == cell.RelayData {
		var err error
		recordSendme, err = c.reserveDataWindows(relayCell.StreamID, c.destUsesCGO())
		if err != nil {
			return err
		}
		reserved = true
	}
	return c.emitRelayCell(relayCell, recordSendme, reserved)
}

// emitRelayCell 在窗口已预留（或非 DATA）后真正加密发出。
func (c *Circuit) emitRelayCell(relayCell *cell.RelayCell, recordSendme, reserved bool) error {
	c.mu.Lock()
	conn := c.conn
	state := c.State
	dest := len(c.Hops) - 1
	destCGO := dest >= 0 && c.Hops[dest].usesCGO()
	c.mu.Unlock()

	refund := func() {
		if reserved {
			c.refundReservedWindows(relayCell.StreamID, destCGO)
			reserved = false
		}
	}

	if state != StateOpen && state != StateBuilding {
		refund()
		return fmt.Errorf("circuit not usable: state=%s", state)
	}

	if conn == nil {
		refund()
		return fmt.Errorf("circuit has no connection")
	}

	var payload []byte
	var err error
	if destCGO {
		payload, err = cell.EncodeRelayCellV1(relayCell)
		if err != nil {
			refund()
			return fmt.Errorf("failed to encode v1 relay cell: %w", err)
		}
		end := cell.V1MessageEnd(payload)
		if end+4 < len(payload) {
			if _, err := rand.Read(payload[end+4:]); err != nil {
				refund()
				return fmt.Errorf("failed to randomize v1 padding: %w", err)
			}
		}
	} else {
		payload, err = relayCell.Encode()
		if err != nil {
			refund()
			return fmt.Errorf("failed to encode relay cell: %w", err)
		}
		if relayCell.Command == cell.RelayData {
			padStart := cell.RelayCellHeaderLen + int(relayCell.Length)
			if padStart < len(payload) {
				if _, err := rand.Read(payload[padStart:]); err != nil {
					refund()
					return fmt.Errorf("failed to randomize DATA padding: %w", err)
				}
			}
		}
	}

	cmd := cell.CmdRelay
	if relayCell.Command == cell.RelayExtend2 || relayCell.Command == cell.RelayExtend {
		cmd = cell.CmdRelayEarly
	}

	var encryptedPayload []byte
	var forwardTag []byte
	if dest >= 0 {
		encryptedPayload, forwardTag, err = c.encryptOnion(byte(cmd), dest, payload)
		if err != nil {
			refund()
			return fmt.Errorf("onion encrypt: %w", err)
		}
	} else {
		encryptedPayload = payload
	}

	cellToSend := &cell.Cell{
		CircID:  c.ID,
		Command: cmd,
		Payload: encryptedPayload,
	}

	// Send through connection (type assert to interface with SendCell method)
	type cellSender interface {
		SendCell(*cell.Cell) error
	}
	sender, ok := conn.(cellSender)
	if !ok {
		refund()
		return fmt.Errorf("connection does not support SendCell")
	}

	if err := sender.SendCell(cellToSend); err != nil {
		refund()
		return fmt.Errorf("failed to send cell: %w", err)
	}

	// 只有真正发出去的 DATA 才入队 SENDME tag，避免未发送 cell 导致 FIFO 失配拆路。
	if recordSendme {
		c.recordSendmeTag(forwardTag)
	}

	// Record activity
	c.RecordActivity()

	return nil
}

// ReceiveRelayCell receives a relay cell from the circuit
// This blocks until a relay cell is received or the context is cancelled
func (c *Circuit) ReceiveRelayCell(ctx context.Context) (*cell.RelayCell, error) {
	select {
	case <-c.destroyCh:
		c.mu.RLock()
		reason := c.destroyReason
		c.mu.RUnlock()
		return nil, fmt.Errorf("circuit destroyed: reason=%d", reason)
	case relayCell, ok := <-c.relayReceiveChan:
		if !ok {
			return nil, fmt.Errorf("circuit closed")
		}
		return relayCell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReceiveRelayCellTimeout receives a relay cell with a timeout
func (c *Circuit) ReceiveRelayCellTimeout(timeout time.Duration) (*cell.RelayCell, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.ReceiveRelayCell(ctx)
}

// DeliverRelayCell delivers a relay cell to this circuit (called by connection layer)
// This decrypts the cell, verifies the digest, handles flow control, and pushes it to the receive channel
func (c *Circuit) DeliverRelayCell(cellData *cell.Cell) error {
	if cellData.CircID != c.ID {
		return fmt.Errorf("circuit ID mismatch: expected %d, got %d", c.ID, cellData.CircID)
	}

	decryptedPayload, hopIdx, onionTag, v1, err := c.decryptOnion(byte(cellData.Command), cellData.Payload)
	if err != nil {
		return fmt.Errorf("onion decrypt: %w", err)
	}

	// SECURITY-001: Validate against replay attacks before processing
	// We check the decrypted payload to ensure the same cell content isn't replayed
	// Using ValidateAndTrackAuto for atomic sequence generation and validation
	if c.replayProtection != nil {
		if err := c.replayProtection.ValidateAndTrackAuto(cell.ReplayBackward, decryptedPayload); err != nil {
			return fmt.Errorf("replay protection: %w", err)
		}
	}

	if hopIdx < 0 {
		// Cell not recognized by any hop
		// This might be a cell for a different stream or an error
		// Per tor-spec.txt §6.1, unrecognized cells should be dropped
		// Silently drop unrecognized cells
		return nil
	}

	var relayCell *cell.RelayCell
	if v1 {
		relayCell, err = cell.DecodeRelayCellV1(decryptedPayload)
	} else {
		relayCell, err = cell.DecodeRelayCell(decryptedPayload)
	}
	if err != nil {
		return fmt.Errorf("failed to decode relay cell: %w", err)
	}

	// Handle flow control per tor-spec.txt §7.4
	switch relayCell.Command {
	case cell.RelayData:
		cellTag := onionTag
		if len(cellTag) == 0 {
			cellTag = c.snapshotBackwardDigest(hopIdx)
		}

		sendSendme, err := c.decrementDeliverWindowAndTakeSendme()
		if err != nil {
			return fmt.Errorf("circuit flow control: %w", err)
		}
		if sendSendme {
			tag := cloneDigest(cellTag)
			go func() {
				if err := c.sendCircuitSendme(tag); err != nil {
					c.SetState(StateFailed)
					c.NotifyDestroyed(1)
				}
			}()
		}

		// v1 识别到的 hop 走 CGO：不能发流级 SENDME，也不减流窗口，
		// 否则 500 个 DATA 后会因发不出 SENDME 而卡死。
		if !v1 && relayCell.StreamID > 0 {
			if err := c.decrementStreamDeliverWindow(relayCell.StreamID); err != nil {
				return fmt.Errorf("stream flow control: %w", err)
			}

			if c.shouldSendStreamSendme(relayCell.StreamID) {
				go func(streamID uint16) {
					if err := c.sendStreamSendme(streamID); err != nil {
						// 流级 SENDME 失败不拆路；电路级 SENDME 仍负责窗口。
					}
				}(relayCell.StreamID)
			}
		}

	case cell.RelaySendme:
		// SENDME cell increments our package window
		if relayCell.StreamID == 0 {
			if err := c.processCircuitSendme(relayCell.Data); err != nil {
				c.SetState(StateFailed)
				c.NotifyDestroyed(1)
				return fmt.Errorf("circuit SENDME: %w", err)
			}
			return nil
		}
		// Stream-level SENDME
		c.incrementStreamPackageWindow(relayCell.StreamID)
		// Don't deliver SENDME cells to the application layer
		return nil
	}

	// Record activity
	c.RecordActivity()

	if set := c.confluxSet(); set != nil {
		handled, err := set.onRelayCell(c, relayCell, hopIdx)
		if err != nil {
			set.failAndClose()
			c.NotifyDestroyed(1)
			return fmt.Errorf("conflux: %w", err)
		}
		if handled {
			return nil
		}
	}

	return c.enqueueRelayCell(relayCell)
}

func (c *Circuit) enqueueRelayCell(relayCell *cell.RelayCell) error {
	c.mu.RLock()
	ch := c.relayReceiveChan
	c.mu.RUnlock()
	if ch == nil {
		return fmt.Errorf("circuit closed")
	}
	// Deliver to receive channel (non-blocking with timeout)
	// AUDIT-MED-4 FIX: Use reusable timer instead of time.After to avoid GC pressure
	c.deliverTimerMu.Lock()
	defer c.deliverTimerMu.Unlock()
	stopAndDrainTimer(c.deliverTimer)
	c.deliverTimer.Reset(deliverRelayCellTimeout)
	select {
	case ch <- relayCell:
		stopAndDrainTimer(c.deliverTimer)
		return nil
	case <-c.deliverTimer.C:
		return fmt.Errorf("relay receive channel full or blocked")
	}
}

const deliverRelayCellTimeout = 100 * time.Millisecond

// stopAndDrainTimer stops a timer and drains its channel if it has already
// fired. When Stop returns false, the timer has either expired or is in the
// process of delivering on C, so draining prevents a stale signal from causing
// the next Reset to time out immediately.
func stopAndDrainTimer(t *time.Timer) {
	if !t.Stop() {
		// Timer already fired, drain the channel
		select {
		case <-t.C:
		default:
		}
	}
}

// OpenStream opens a new stream on this circuit
// This is a convenience method that integrates with the stream manager
// AUDIT-MED-2 FIX: Now accepts context parameter to respect caller's cancellation
func (c *Circuit) OpenStream(ctx context.Context, streamID uint16, target string, port uint16) error {
	// Send RELAY_BEGIN cell
	beginPayload := encodeBeginAddrPort(target, port)
	beginCell, err := cell.NewRelayCell(streamID, cell.RelayBegin, beginPayload)
	if err != nil {
		return fmt.Errorf("failed to create RELAY_BEGIN cell: %w", err)
	}

	if err := c.SendRelayCell(beginCell); err != nil {
		return fmt.Errorf("failed to send RELAY_BEGIN: %w", err)
	}

	// Wait for RELAY_CONNECTED response with caller's context and 30s timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	connectedCell, err := c.ReceiveRelayCell(timeoutCtx)
	if err != nil {
		return fmt.Errorf("failed to receive RELAY_CONNECTED: %w", err)
	}

	if connectedCell.StreamID != streamID {
		// Not for this stream, put it back?
		// For now, error out
		return fmt.Errorf("received cell for wrong stream: expected %d, got %d", streamID, connectedCell.StreamID)
	}

	if connectedCell.Command == cell.RelayEnd {
		// Stream was rejected
		reason := "unknown"
		if len(connectedCell.Data) > 0 {
			reason = fmt.Sprintf("reason=%d", connectedCell.Data[0])
		}
		return fmt.Errorf("stream rejected by exit: %s", reason)
	}

	if connectedCell.Command != cell.RelayConnected {
		return fmt.Errorf("expected RELAY_CONNECTED, got %s", cell.RelayCmdString(connectedCell.Command))
	}

	return nil
}

// ReadFromStream reads data from a specific stream
// This is used by the SOCKS proxy to receive data from the exit node
func (c *Circuit) ReadFromStream(ctx context.Context, streamID uint16) ([]byte, error) {
	for {
		relayCell, err := c.ReceiveRelayCell(ctx)
		if err != nil {
			if err == io.EOF {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("failed to receive relay cell: %w", err)
		}

		// Filter for our stream
		if relayCell.StreamID != streamID {
			// Cell for different stream, deliver to stream manager
			if err := c.deliverToStream(relayCell); err != nil {
				// Log error but continue - stream might not exist yet or be closed
				// In production, this should use proper logging
			}
			continue
		}

		switch relayCell.Command {
		case cell.RelayData:
			return relayCell.Data, nil
		case cell.RelayEnd:
			return nil, io.EOF
		default:
			// Unexpected command for this stream
			continue
		}
	}
}

// RelayDataMax 返回本电路目的跳上一条 RELAY_DATA 能装的最大字节。
// CGO/v1 带 stream_id 时是 488，不是 v0 的 498。
func (c *Circuit) RelayDataMax() int {
	if set := c.confluxSet(); set != nil && c.ConfluxLinked() {
		return set.relayDataMax()
	}
	return c.relayDataMaxLocal()
}

// WriteToStream writes data to a specific stream
// This is used by the SOCKS proxy to send data to the exit node
func (c *Circuit) WriteToStream(streamID uint16, data []byte) error {
	max := c.RelayDataMax()
	for len(data) > 0 {
		n := len(data)
		if n > max {
			n = max
		}
		dataCell, err := cell.NewRelayCell(streamID, cell.RelayData, data[:n])
		if err != nil {
			return fmt.Errorf("failed to create RELAY_DATA cell: %w", err)
		}
		if err := c.SendRelayCell(dataCell); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// EndStream sends a RELAY_END cell for a stream
func (c *Circuit) EndStream(streamID uint16, reason byte) error {
	endCell, err := cell.NewRelayCell(streamID, cell.RelayEnd, []byte{reason})
	if err != nil {
		return fmt.Errorf("failed to create RELAY_END cell: %w", err)
	}
	return c.SendRelayCell(endCell)
}

// SECURITY-001: Replay protection methods

// GetReplayStats returns replay protection statistics for this circuit.
// This is useful for monitoring and debugging replay detection.
func (c *Circuit) GetReplayStats() cell.Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.replayProtection == nil {
		return cell.Stats{}
	}
	return c.replayProtection.Stats()
}

// GetReplayAttempts returns the total number of detected replay attempts.
func (c *Circuit) GetReplayAttempts() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.replayProtection == nil {
		return 0
	}
	return c.replayProtection.TotalReplayAttempts()
}

// ValidateCellForReplay validates a cell against replay attacks.
// This is called during cell processing to detect replayed cells.
// direction: cell.ReplayForward for outgoing, cell.ReplayBackward for incoming
// Uses atomic sequence generation and validation to prevent race conditions.
func (c *Circuit) ValidateCellForReplay(direction cell.ReplayDirection, cellData []byte) error {
	c.mu.RLock()
	rp := c.replayProtection
	c.mu.RUnlock()

	if rp == nil {
		return nil // Replay protection not initialized (shouldn't happen)
	}

	// Use atomic validation method that generates sequence and validates together
	return rp.ValidateAndTrackAuto(direction, cellData)
}

// ResetReplayProtection resets the replay protection state.
// This should be called when the circuit is torn down or when
// a new circuit is established on the same Circuit object.
func (c *Circuit) ResetReplayProtection() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.replayProtection != nil {
		c.replayProtection.Reset()
	}
}
