// Package stream provides Tor stream management for multiplexing connections over circuits.
//
// # Flow Control
//
// This package implements stream-level flow control per tor-spec.txt §7.4.
// Both circuit-level and stream-level flow control use a sliding window protocol
// to prevent buffer exhaustion.
//
// Stream-level flow control parameters:
//   - Initial window size: 500 cells
//   - SENDME threshold: 50 cells (send SENDME every 50 DATA cells received)
//   - SENDME increment: 50 cells (each SENDME increases window by 50)
//
// The package window tracks outgoing cells (cells we can send), while the
// deliver window tracks incoming cells (cells we can receive). When either
// window is exhausted, data transmission is blocked until a SENDME is received.
//
// For circuit-level flow control, see pkg/circuit/circuit.go.
package stream

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// State represents the current state of a stream
type State int

const (
	// StateNew indicates the stream is newly created
	StateNew State = iota
	// StateConnecting indicates the stream is connecting
	StateConnecting
	// StateConnected indicates the stream is connected and ready
	StateConnected
	// StateClosed indicates the stream has been closed
	StateClosed
	// StateFailed indicates the stream failed
	StateFailed
)

// String returns a string representation of the state
func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateConnecting:
		return "CONNECTING"
	case StateConnected:
		return "CONNECTED"
	case StateClosed:
		return "CLOSED"
	case StateFailed:
		return "FAILED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// Stream represents a single connection multiplexed over a circuit
type Stream struct {
	ID           uint16
	CircuitID    uint32
	Target       string
	Port         uint16
	State        State
	IsolationKey *circuit.IsolationKey // Isolation key for this stream
	CreatedAt    time.Time
	sendQueue    chan []byte
	recvQueue    chan []byte
	closeChan    chan struct{}
	closeOnce    sync.Once
	mu           sync.RWMutex
	logger       *logger.Logger
	// Flow control per tor-spec.txt §7.4
	packageWindow  int // Stream-level package window (cells we can send)
	deliverWindow  int // Stream-level deliver window (cells we can receive)
	sendmeReceived int // Count of DATA cells received (for sending SENDME)
	sendmeSent     int // Count of SENDME cells sent
	// Backpressure state for memory management
	backpressure   *BackpressureState // Optional backpressure controller
	sendBufferSize int                // Current send buffer size in bytes
	recvBufferSize int                // Current recv buffer size in bytes
}

// NewStream creates a new stream
func NewStream(id uint16, circuitID uint32, target string, port uint16, log *logger.Logger) *Stream {
	if log == nil {
		log = logger.NewDefault()
	}

	return &Stream{
		ID:             id,
		CircuitID:      circuitID,
		Target:         target,
		Port:           port,
		State:          StateNew,
		CreatedAt:      time.Now(),
		sendQueue:      make(chan []byte, 32),
		recvQueue:      make(chan []byte, 32),
		closeChan:      make(chan struct{}),
		logger:         log.Component("stream"),
		packageWindow:  500, // tor-spec.txt §7.4: Initial stream window is 500
		deliverWindow:  500, // tor-spec.txt §7.4: Initial stream window is 500
		sendmeReceived: 0,
		sendmeSent:     0,
	}
}

// SetState updates the stream state
func (s *Stream) SetState(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldState := s.State
	s.State = state
	s.logger.Debug("Stream state transition",
		"stream_id", s.ID,
		"old_state", oldState,
		"new_state", state)
}

// GetState returns the current stream state
func (s *Stream) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

// Send queues data to be sent on the stream
func (s *Stream) Send(data []byte) error {
	if s.GetState() != StateConnected {
		return fmt.Errorf("stream not connected: state=%s", s.GetState())
	}

	// Check backpressure before attempting to send
	if s.backpressure != nil {
		s.mu.Lock()
		potentialSize := s.sendBufferSize + len(data)
		isPaused := s.backpressure.CheckSendBuffer(potentialSize)
		s.mu.Unlock()

		if isPaused {
			return fmt.Errorf("send buffer full (backpressure applied)")
		}
	}

	select {
	case s.sendQueue <- data:
		// Successfully queued - now update buffer size
		if s.backpressure != nil {
			s.mu.Lock()
			s.sendBufferSize += len(data)
			s.mu.Unlock()
		}
		return nil
	case <-s.closeChan:
		return io.EOF
	default:
		return fmt.Errorf("send queue full")
	}
}

// Receive reads data from the stream
func (s *Stream) Receive(ctx context.Context) ([]byte, error) {
	select {
	case data := <-s.recvQueue:
		// Update buffer size and check if backpressure can be released
		if s.backpressure != nil {
			s.mu.Lock()
			s.recvBufferSize -= len(data)
			if s.recvBufferSize < 0 {
				s.recvBufferSize = 0
			}
			s.backpressure.CheckRecvBuffer(s.recvBufferSize)
			s.mu.Unlock()
		}
		return data, nil
	case <-s.closeChan:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReceiveData delivers received data to the stream (called by circuit layer)
func (s *Stream) ReceiveData(data []byte) error {
	// Check backpressure before accepting data
	if s.backpressure != nil {
		s.mu.Lock()
		potentialSize := s.recvBufferSize + len(data)
		isPaused := s.backpressure.CheckRecvBuffer(potentialSize)
		s.mu.Unlock()

		if isPaused {
			return fmt.Errorf("receive buffer full (backpressure applied)")
		}
	}

	select {
	case s.recvQueue <- data:
		// Successfully queued - now update buffer size
		if s.backpressure != nil {
			s.mu.Lock()
			s.recvBufferSize += len(data)
			s.mu.Unlock()
		}
		return nil
	case <-s.closeChan:
		return io.EOF
	default:
		return fmt.Errorf("receive queue full")
	}
}

// SendData retrieves data to be sent (called by circuit layer)
func (s *Stream) SendData(ctx context.Context) ([]byte, error) {
	select {
	case data := <-s.sendQueue:
		// Update buffer size and check if backpressure can be released
		if s.backpressure != nil {
			s.mu.Lock()
			s.sendBufferSize -= len(data)
			if s.sendBufferSize < 0 {
				s.sendBufferSize = 0
			}
			s.backpressure.CheckSendBuffer(s.sendBufferSize)
			s.mu.Unlock()
		}
		return data, nil
	case <-s.closeChan:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close closes the stream
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeChan)
		s.SetState(StateClosed)
		s.logger.Info("Stream closed",
			"stream_id", s.ID,
			"circuit_id", s.CircuitID)
	})
	return nil
}

// streamKey 标识一条流。Tor StreamID 在每条电路内独立编号，不得做进程内全局唯一。
type streamKey struct {
	circuitID uint32
	streamID  uint16
}

// Manager manages multiple streams across circuits
type Manager struct {
	streams   map[streamKey]*Stream
	nextID    map[uint32]uint16 // 每条电路各自的下一候选 StreamID（CreateStream 用）
	mu        sync.RWMutex
	logger    *logger.Logger
	closeChan chan struct{}
	closeOnce sync.Once
}

// NewManager creates a new stream manager
func NewManager(log *logger.Logger) *Manager {
	if log == nil {
		log = logger.NewDefault()
	}

	return &Manager{
		streams:   make(map[streamKey]*Stream),
		nextID:    make(map[uint32]uint16),
		logger:    log.Component("stream-manager"),
		closeChan: make(chan struct{}),
	}
}

// CreateStream creates a new stream for a target
func (m *Manager) CreateStream(circuitID uint32, target string, port uint16) (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case <-m.closeChan:
		return nil, fmt.Errorf("manager closed")
	default:
	}

	next := m.nextID[circuitID]
	if next == 0 {
		next = 1
	}
	start := next
	for {
		id := next
		next++
		if next == 0 {
			next = 1
		}
		key := streamKey{circuitID: circuitID, streamID: id}
		if _, exists := m.streams[key]; !exists {
			m.nextID[circuitID] = next
			return m.addStreamLocked(id, circuitID, target, port)
		}
		if next == start {
			return nil, fmt.Errorf("no free stream IDs on circuit %d", circuitID)
		}
	}
}

// CreateStreamWithID 用电路分配器给出的非 0 StreamID 建流。
// SOCKS BEGIN 与 RELAY_RESOLVE 必须共用**该电路**上的 ID 空间；不同电路可复用同一 StreamID。
func (m *Manager) CreateStreamWithID(id uint16, circuitID uint32, target string, port uint16) (*Stream, error) {
	if id == 0 {
		return nil, fmt.Errorf("stream ID 0 is reserved (not a valid BEGIN/RESOLVE stream)")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case <-m.closeChan:
		return nil, fmt.Errorf("manager closed")
	default:
	}

	key := streamKey{circuitID: circuitID, streamID: id}
	if _, exists := m.streams[key]; exists {
		return nil, fmt.Errorf("stream ID %d already in use on circuit %d", id, circuitID)
	}
	next := m.nextID[circuitID]
	if next == 0 || id >= next {
		n := id + 1
		if n == 0 {
			n = 1
		}
		m.nextID[circuitID] = n
	}
	return m.addStreamLocked(id, circuitID, target, port)
}

func (m *Manager) addStreamLocked(streamID uint16, circuitID uint32, target string, port uint16) (*Stream, error) {
	stream := NewStream(streamID, circuitID, target, port, m.logger)
	m.streams[streamKey{circuitID: circuitID, streamID: streamID}] = stream

	m.logger.Info("Stream created",
		"stream_id", streamID,
		"circuit_id", circuitID,
		"target", target,
		"port", port)

	return stream, nil
}

// GetStream 按电路与 StreamID 取流。
func (m *Manager) GetStream(circuitID uint32, streamID uint16) (*Stream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stream, exists := m.streams[streamKey{circuitID: circuitID, streamID: streamID}]
	if !exists {
		return nil, fmt.Errorf("stream not found: circuit=%d stream=%d", circuitID, streamID)
	}

	return stream, nil
}

// RemoveStream 从管理器移除指定电路上的流。
func (m *Manager) RemoveStream(circuitID uint32, streamID uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := streamKey{circuitID: circuitID, streamID: streamID}
	stream, exists := m.streams[key]
	if !exists {
		return fmt.Errorf("stream not found: circuit=%d stream=%d", circuitID, streamID)
	}

	if err := stream.Close(); err != nil {
		m.logger.Error("Failed to close stream during removal", "function", "RemoveStream", "stream_id", streamID, "circuit_id", circuitID, "error", err)
	}
	delete(m.streams, key)

	m.logger.Info("Stream removed", "stream_id", streamID, "circuit_id", circuitID)

	return nil
}

// GetStreamsForCircuit returns all streams on a circuit
func (m *Manager) GetStreamsForCircuit(circuitID uint32) []*Stream {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var streams []*Stream
	for key, stream := range m.streams {
		if key.circuitID == circuitID {
			streams = append(streams, stream)
		}
	}

	return streams
}

// Close closes all streams and the manager
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		close(m.closeChan)

		m.mu.Lock()
		defer m.mu.Unlock()

		for key, stream := range m.streams {
			if err := stream.Close(); err != nil {
				m.logger.Error("Failed to close stream during shutdown", "function", "Close", "stream_id", key.streamID, "circuit_id", key.circuitID, "error", err)
			}
			delete(m.streams, key)
		}

		m.logger.Info("Stream manager closed")
	})

	return nil
}

// CircuitBound 是绑定到单条电路的流视图，供 circuit.SetStreamManager 使用。
// GetStream(uint16) 只在该电路的 ID 空间内查找，符合 Tor「StreamID 按电路独立」语义。
type CircuitBound struct {
	mgr       *Manager
	circuitID uint32
}

// BoundToCircuit 返回仅操作指定电路流的视图。
func (m *Manager) BoundToCircuit(circuitID uint32) *CircuitBound {
	return &CircuitBound{mgr: m, circuitID: circuitID}
}

// GetStream 实现电路侧 streamGetter 接口。
func (b *CircuitBound) GetStream(streamID uint16) (interface{}, error) {
	if b == nil || b.mgr == nil {
		return nil, fmt.Errorf("stream manager not bound")
	}
	return b.mgr.GetStream(b.circuitID, streamID)
}

// Count returns the number of active streams
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// SetIsolationKey sets the isolation key for a stream
func (s *Stream) SetIsolationKey(key *circuit.IsolationKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IsolationKey = key
}

// GetIsolationKey returns the isolation key for a stream
func (s *Stream) GetIsolationKey() *circuit.IsolationKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.IsolationKey
}

// DecrementPackageWindow decrements the stream-level package window
// Returns an error if the window is exhausted
func (s *Stream) DecrementPackageWindow() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.packageWindow <= 0 {
		return fmt.Errorf("%w: cannot send more cells until SENDME received", circuit.ErrWindowExhausted)
	}

	s.packageWindow--
	return nil
}

// IncrementPackageWindow increments the stream-level package window
// This is called when we receive a SENDME cell for this stream
func (s *Stream) IncrementPackageWindow() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Per tor-spec.txt §7.4, each stream SENDME increments the window by 50
	s.packageWindow += 50
	s.sendmeSent++
}

// RefundPackageWindow 在预留流窗后发送失败时退还一格，不是收到 SENDME。
func (s *Stream) RefundPackageWindow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packageWindow++
}

// DecrementDeliverWindow decrements the stream-level deliver window
// Returns an error if the window is exhausted
func (s *Stream) DecrementDeliverWindow() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.deliverWindow <= 0 {
		return fmt.Errorf("stream deliver window exhausted: cannot receive more cells until SENDME sent")
	}

	s.deliverWindow--
	s.sendmeReceived++

	return nil
}

// ShouldSendStreamSendme checks if we should send a stream-level SENDME
// Per tor-spec.txt §7.4, send SENDME every 50 cells received
func (s *Stream) ShouldSendStreamSendme() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.sendmeReceived >= 50
}

// RecordStreamSendmeSent records that a stream-level SENDME was sent
// This resets the received counter and increments the deliver window
func (s *Stream) RecordStreamSendmeSent() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sendmeReceived = 0
	s.deliverWindow += 50 // Increment our deliver window
}

// GetPackageWindow returns the current package window (for testing)
func (s *Stream) GetPackageWindow() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.packageWindow
}

// GetDeliverWindow returns the current deliver window (for testing)
func (s *Stream) GetDeliverWindow() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deliverWindow
}

// SetBackpressure attaches a backpressure controller to this stream
func (s *Stream) SetBackpressure(bp *BackpressureState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backpressure = bp
}

// GetBackpressure returns the current backpressure state
func (s *Stream) GetBackpressure() *BackpressureState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backpressure
}

// GetSendBufferSize returns the current send buffer size in bytes
func (s *Stream) GetSendBufferSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sendBufferSize
}

// GetRecvBufferSize returns the current receive buffer size in bytes
func (s *Stream) GetRecvBufferSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recvBufferSize
}
