// Package circuit provides padding machine state management per padding-spec.txt
package circuit

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// PaddingMachineType identifies different padding machine implementations
type PaddingMachineType byte

const (
	// PaddingMachineNone indicates no padding machine is active
	PaddingMachineNone PaddingMachineType = 0
	// PaddingMachineCircuitSetup is CIRCPAD_MACHINE_CIRC_SETUP（proposal 302 / padding-spec = 1）
	PaddingMachineCircuitSetup PaddingMachineType = PaddingMachineType(CircpadMachineCircSetup)
	// PaddingMachineAPE is a local Adaptive Padding Engine（不上线路 negotiate）
	PaddingMachineAPE PaddingMachineType = 2
)

// PaddingMachineState represents the current state of a padding machine
type PaddingMachineState byte

const (
	// MachineStateStart is the initial state
	MachineStateStart PaddingMachineState = 0
	// MachineStateBurst is when padding cells are sent in bursts
	MachineStateBurst PaddingMachineState = 1
	// MachineStateGap is the idle period between bursts
	MachineStateGap PaddingMachineState = 2
	// MachineStateEnd is the terminal state
	MachineStateEnd PaddingMachineState = 3
)

// String returns a human-readable state name
func (s PaddingMachineState) String() string {
	switch s {
	case MachineStateStart:
		return "START"
	case MachineStateBurst:
		return "BURST"
	case MachineStateGap:
		return "GAP"
	case MachineStateEnd:
		return "END"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// StateMachine implements a formal padding state machine per padding-spec.txt
type StateMachine struct {
	mu          sync.RWMutex
	machineType PaddingMachineType
	state       PaddingMachineState
	circuit     *Circuit

	// State transition parameters
	burstMin  int           // Minimum cells in a burst
	burstMax  int           // Maximum cells in a burst
	gapMin    time.Duration // Minimum gap between bursts
	gapMax    time.Duration // Maximum gap between bursts
	cellDelay time.Duration // Delay between cells within a burst

	// Runtime state
	cellsInBurst  int       // Cells sent in current burst
	burstTarget   int       // Target cells for current burst
	lastSentTime  time.Time // Last time we sent a padding cell
	nextEventTime time.Time // When next state transition should occur

	// Statistics
	totalPaddingSent uint64
	burstCount       uint64
}

// PaddingMachineParams contains configurable parameters for padding machines
// These can be set from consensus parameters via directory.GetPaddingParams()
type PaddingMachineParams struct {
	BurstMin  int           // Minimum cells in a burst
	BurstMax  int           // Maximum cells in a burst
	GapMin    time.Duration // Minimum gap between bursts
	GapMax    time.Duration // Maximum gap between bursts
	CellDelay time.Duration // Delay between cells within a burst
}

// DefaultAPEParams returns default parameters for APE machine per padding-spec.txt §3
func DefaultAPEParams() *PaddingMachineParams {
	return &PaddingMachineParams{
		BurstMin:  2,
		BurstMax:  10,
		GapMin:    1500 * time.Millisecond,
		GapMax:    9500 * time.Millisecond,
		CellDelay: 20 * time.Millisecond,
	}
}

// DefaultCircuitSetupParams returns default parameters for circuit setup machine
func DefaultCircuitSetupParams() *PaddingMachineParams {
	return &PaddingMachineParams{
		BurstMin:  1,
		BurstMax:  5,
		GapMin:    500 * time.Millisecond,
		GapMax:    2000 * time.Millisecond,
		CellDelay: 50 * time.Millisecond,
	}
}

// NewAPEMachine creates an Adaptive Padding Engine state machine
// Parameters are based on padding-spec.txt recommendations
func NewAPEMachine(circuit *Circuit) *StateMachine {
	return NewAPEMachineWithParams(circuit, DefaultAPEParams())
}

// NewAPEMachineWithParams creates an APE machine with custom parameters from consensus
func NewAPEMachineWithParams(circuit *Circuit, params *PaddingMachineParams) *StateMachine {
	return &StateMachine{
		machineType: PaddingMachineAPE,
		state:       MachineStateStart,
		circuit:     circuit,
		burstMin:    params.BurstMin,
		burstMax:    params.BurstMax,
		gapMin:      params.GapMin,
		gapMax:      params.GapMax,
		cellDelay:   params.CellDelay,
	}
}

// NewCircuitSetupMachine creates a padding machine for circuit setup phase
func NewCircuitSetupMachine(circuit *Circuit) *StateMachine {
	return NewCircuitSetupMachineWithParams(circuit, DefaultCircuitSetupParams())
}

// NewCircuitSetupMachineWithParams creates a circuit setup machine with custom parameters
func NewCircuitSetupMachineWithParams(circuit *Circuit, params *PaddingMachineParams) *StateMachine {
	return &StateMachine{
		machineType: PaddingMachineCircuitSetup,
		state:       MachineStateStart,
		circuit:     circuit,
		burstMin:    params.BurstMin,
		burstMax:    params.BurstMax,
		gapMin:      params.GapMin,
		gapMax:      params.GapMax,
		cellDelay:   params.CellDelay,
	}
}

// Start transitions the machine from START to BURST state
func (sm *StateMachine) Start() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != MachineStateStart {
		return fmt.Errorf("cannot start from state %s", sm.state)
	}

	sm.state = MachineStateBurst
	sm.burstTarget = sm.randomRange(sm.burstMin, sm.burstMax)
	sm.cellsInBurst = 0
	sm.burstCount++
	return nil
}

// ProcessEvent handles state machine events (cell sent, timeout, etc.)
// Returns true if a padding cell should be sent
func (sm *StateMachine) ProcessEvent() (shouldPad bool, nextDelay time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()

	switch sm.state {
	case MachineStateStart:
		// Should not be in START state during processing
		return false, time.Hour

	case MachineStateBurst:
		// Check if we should send another cell in this burst
		if sm.cellsInBurst < sm.burstTarget {
			// Send a cell after cellDelay
			timeSinceLastCell := now.Sub(sm.lastSentTime)
			if timeSinceLastCell >= sm.cellDelay || sm.cellsInBurst == 0 {
				sm.cellsInBurst++
				sm.lastSentTime = now
				sm.totalPaddingSent++

				// Check if burst is complete
				if sm.cellsInBurst >= sm.burstTarget {
					sm.transitionToGap()
					return true, sm.randomDuration(sm.gapMin, sm.gapMax)
				}
				return true, sm.cellDelay
			}
			return false, sm.cellDelay - timeSinceLastCell
		}

		// Burst complete, transition to GAP
		sm.transitionToGap()
		return false, sm.randomDuration(sm.gapMin, sm.gapMax)

	case MachineStateGap:
		// Check if gap period is over
		if now.After(sm.nextEventTime) {
			sm.transitionToBurst()
			return false, sm.cellDelay // Start next burst soon
		}
		return false, time.Until(sm.nextEventTime)

	case MachineStateEnd:
		return false, time.Hour // Machine stopped

	default:
		return false, time.Hour
	}
}

// transitionToGap moves from BURST to GAP state
func (sm *StateMachine) transitionToGap() {
	sm.state = MachineStateGap
	gapDuration := sm.randomDuration(sm.gapMin, sm.gapMax)
	sm.nextEventTime = time.Now().Add(gapDuration)
}

// transitionToBurst moves from GAP to BURST state
func (sm *StateMachine) transitionToBurst() {
	sm.state = MachineStateBurst
	sm.burstTarget = sm.randomRange(sm.burstMin, sm.burstMax)
	sm.cellsInBurst = 0
	sm.burstCount++
}

// Stop transitions the machine to END state
func (sm *StateMachine) Stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = MachineStateEnd
}

// GetState returns the current state
func (sm *StateMachine) GetState() PaddingMachineState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// GetStats returns statistics about the machine
func (sm *StateMachine) GetStats() StateMachineStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return StateMachineStats{
		State:            sm.state,
		TotalPaddingSent: sm.totalPaddingSent,
		BurstCount:       sm.burstCount,
	}
}

// StateMachineStats contains statistics about a padding machine
type StateMachineStats struct {
	State            PaddingMachineState
	TotalPaddingSent uint64
	BurstCount       uint64
}

// randomRange returns a random integer in [min, max]
func (sm *StateMachine) randomRange(min, max int) int {
	if min >= max {
		return min
	}
	rangeSize := uint32(max - min + 1)
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return min // Fallback on error
	}
	n := binary.BigEndian.Uint32(buf[:])
	return min + int(n%rangeSize)
}

// randomDuration returns a cryptographically random duration between min and max
func (sm *StateMachine) randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	rangeSize := uint64(max - min)
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return min // Fallback on error
	}
	n := binary.BigEndian.Uint64(buf[:])
	return min + time.Duration(n%rangeSize)
}

// PaddingNegotiateRequest represents a PADDING_NEGOTIATE cell payload.
// Deprecated: 请使用 CircpadNegotiate（含 machine_ctr，符合 padding-spec）。
type PaddingNegotiateRequest struct {
	Version     byte               // Protocol version (0 for now)
	Command     byte               // 1 = STOP, 2 = START（padding-spec）
	MachineType PaddingMachineType // Type of padding machine to negotiate
	MachineCtr  uint32
}

// PaddingNegotiateResponse represents a PADDING_NEGOTIATED cell payload.
// Deprecated: 请使用 CircpadNegotiated。
type PaddingNegotiateResponse struct {
	Version     byte               // Protocol version (0 for now)
	Command     byte               // STOP=1 / START=2
	Response    byte               // OK=1 / ERR=2
	MachineType PaddingMachineType // Type of padding machine negotiated
	MachineCtr  uint32
}

// Padding negotiate commands（与 CircpadCommand* 一致；旧名保留）。
const (
	PaddingCommandStop  byte = CircpadCommandStop  // 1
	PaddingCommandStart byte = CircpadCommandStart // 2
)

// Padding negotiate responses（与 CircpadResponse* 一致）。
const (
	PaddingResponseOK      byte = CircpadResponseOK  // 1
	PaddingResponseErr     byte = CircpadResponseErr // 2
	PaddingResponseStarted byte = CircpadResponseOK  // 兼容旧测试名
	PaddingResponseStopped byte = CircpadResponseOK
	PaddingResponseError   byte = CircpadResponseErr
)

// EncodePaddingNegotiate 编码 PADDING_NEGOTIATE（8 字节，含 machine_ctr）。
func EncodePaddingNegotiate(req *PaddingNegotiateRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	return EncodeCircpadNegotiate(&CircpadNegotiate{
		Version:     req.Version,
		Command:     req.Command,
		MachineType: byte(req.MachineType),
		MachineCtr:  req.MachineCtr,
	})
}

// DecodePaddingNegotiate 解码 PADDING_NEGOTIATE。
func DecodePaddingNegotiate(data []byte) (*PaddingNegotiateRequest, error) {
	n, err := DecodeCircpadNegotiate(data)
	if err != nil {
		return nil, err
	}
	return &PaddingNegotiateRequest{
		Version:     n.Version,
		Command:     n.Command,
		MachineType: PaddingMachineType(n.MachineType),
		MachineCtr:  n.MachineCtr,
	}, nil
}

// EncodePaddingNegotiated 编码 PADDING_NEGOTIATED（8 字节）。
func EncodePaddingNegotiated(resp *PaddingNegotiateResponse) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("response cannot be nil")
	}
	return EncodeCircpadNegotiated(&CircpadNegotiated{
		Version:     resp.Version,
		Command:     resp.Command,
		Response:    resp.Response,
		MachineType: byte(resp.MachineType),
		MachineCtr:  resp.MachineCtr,
	})
}

// DecodePaddingNegotiated 解码 PADDING_NEGOTIATED。
func DecodePaddingNegotiated(data []byte) (*PaddingNegotiateResponse, error) {
	n, err := DecodeCircpadNegotiated(data)
	if err != nil {
		return nil, err
	}
	return &PaddingNegotiateResponse{
		Version:     n.Version,
		Command:     n.Command,
		Response:    n.Response,
		MachineType: PaddingMachineType(n.MachineType),
		MachineCtr:  n.MachineCtr,
	}, nil
}

// SendPaddingNegotiate sends a PADDING_NEGOTIATE cell to negotiate padding
func (c *Circuit) SendPaddingNegotiate(machineType PaddingMachineType, start bool) error {
	cmd := PaddingCommandStop
	if start {
		cmd = PaddingCommandStart
	}

	req := &PaddingNegotiateRequest{
		Version:     0,
		Command:     cmd,
		MachineType: machineType,
		MachineCtr:  1,
	}

	payload, err := EncodePaddingNegotiate(req)
	if err != nil {
		return fmt.Errorf("failed to encode padding negotiate: %w", err)
	}

	relayCell, err := cell.NewRelayCell(0, cell.RelayPaddingNegotiate, payload)
	if err != nil {
		return fmt.Errorf("failed to create relay cell: %w", err)
	}

	return c.SendRelayCell(relayCell)
}

// HandlePaddingNegotiate processes an incoming PADDING_NEGOTIATE cell
func (c *Circuit) HandlePaddingNegotiate(data []byte) error {
	req, err := DecodePaddingNegotiate(data)
	if err != nil {
		return fmt.Errorf("failed to decode padding negotiate: %w", err)
	}

	respCmd := req.Command
	response := PaddingResponseOK
	if req.MachineType != PaddingMachineType(CircpadMachineCircSetup) && req.MachineType != PaddingMachineCircuitSetup {
		response = PaddingResponseErr
	}

	resp := &PaddingNegotiateResponse{
		Version:     0,
		Command:     respCmd,
		Response:    response,
		MachineType: req.MachineType,
		MachineCtr:  req.MachineCtr,
	}

	payload, err := EncodePaddingNegotiated(resp)
	if err != nil {
		return fmt.Errorf("failed to encode padding negotiated: %w", err)
	}

	relayCell, err := cell.NewRelayCell(0, cell.RelayPaddingNegotiated, payload)
	if err != nil {
		return fmt.Errorf("failed to create relay cell: %w", err)
	}

	return c.SendRelayCell(relayCell)
}
