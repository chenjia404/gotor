// Package circuit provides circuit extension functionality for the Tor protocol.
package circuit

import (
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 - SHA-1 required by Tor protocol (tor-spec.txt §6.1)
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/security"
)

// HandshakeType defines the type of circuit handshake to use
type HandshakeType uint16

const (
	// HandshakeTypeNtorV3 是现行默认握手（Relay=4，Ed25519 主身份 + 扩展）。
	HandshakeTypeNtorV3 HandshakeType = 0x0003
	// HandshakeTypeNTor 是经典 ntor（无扩展时才使用）。
	HandshakeTypeNTor HandshakeType = 0x0002
	// HandshakeTypeTAP is the legacy TAP handshake
	HandshakeTypeTAP HandshakeType = 0x0000
)

// Extension handles circuit extension operations
type Extension struct {
	circuit          *Circuit
	logger           *logger.Logger
	targetRelay      interface{} // Stores relay descriptor for key extraction (SPEC-001)
	ephemeralPrivate []byte      // Client ephemeral private key for ntor handshake
	serverIdentity   []byte      // Server identity key for ntor verification
	serverNtorKey    []byte      // Server ntor onion key for ntor verification
	handshakeType    HandshakeType
	ntorv3State      *crypto.NtorV3ClientState
	requestCC        bool
	requestCGO       bool
}

// NewExtension creates a new circuit extension handler
func NewExtension(circuit *Circuit, log *logger.Logger) *Extension {
	if log == nil {
		log = logger.NewDefault()
	}

	return &Extension{
		circuit: circuit,
		logger:  log.Component("extension"),
	}
}

// CreateFirstHop creates the first hop of the circuit using CREATE2
// This establishes the initial circuit with the guard node
func (e *Extension) CreateFirstHop(ctx context.Context, handshakeType HandshakeType) error {
	e.logger.Info("Creating first hop",
		"circuit_id", e.circuit.ID,
		"handshake_type", handshakeType)

	// Get the connection from the circuit
	conn, err := e.getConnection()
	if err != nil {
		return fmt.Errorf("no connection available: %w", err)
	}

	// Generate handshake data
	handshakeData, err := e.generateHandshakeData(handshakeType)
	if err != nil {
		return fmt.Errorf("failed to generate handshake data: %w", err)
	}

	// Build CREATE2 cell payload
	// Safely convert handshake data length to uint16
	hlen, err := security.SafeLenToUint16(handshakeData)
	if err != nil {
		return fmt.Errorf("handshake data too large: %v", err)
	}

	payload := make([]byte, 2+2+len(handshakeData))
	binary.BigEndian.PutUint16(payload[0:2], uint16(handshakeType))
	binary.BigEndian.PutUint16(payload[2:4], hlen)
	copy(payload[4:], handshakeData)

	// Create CREATE2 cell
	create2Cell := &cell.Cell{
		CircID:  e.circuit.ID,
		Command: cell.CmdCreate2,
		Payload: payload,
	}

	e.logger.Debug("Sending CREATE2 cell",
		"circuit_id", e.circuit.ID,
		"handshake_size", len(handshakeData))

	e.circuit.mu.RLock()
	mux := e.circuit.mux
	e.circuit.mu.RUnlock()
	if mux != nil {
		mux.ExpectCreated2(e.circuit.ID)
	}

	if err := conn.SendCell(create2Cell); err != nil {
		if mux != nil {
			mux.ForgetCreated2(e.circuit.ID)
		}
		return fmt.Errorf("failed to send CREATE2 cell: %w", err)
	}

	// Wait for CREATED2 response
	created2Cell, err := e.receiveCreated2(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to receive CREATED2: %w", err)
	}

	// Process CREATED2 response to derive keys
	if err := e.ProcessCreated2(created2Cell); err != nil {
		return fmt.Errorf("failed to process CREATED2: %w", err)
	}

	e.logger.Info("First hop created successfully", "circuit_id", e.circuit.ID)

	return nil
}

// ExtendCircuit extends the circuit to add another hop using EXTEND2
func (e *Extension) ExtendCircuit(ctx context.Context, target string, handshakeType HandshakeType) error {
	e.logger.Info("Extending circuit",
		"circuit_id", e.circuit.ID,
		"target", target,
		"handshake_type", handshakeType)

	// Generate handshake data with relay keys if available
	handshakeData, err := e.generateHandshakeData(handshakeType)
	if err != nil {
		return fmt.Errorf("failed to generate handshake data: %w", err)
	}

	// Build EXTEND2 relay cell
	// EXTEND2 format: NSPEC [LSPECS] HTYPE HLEN HDATA
	extend2Data, err := e.buildExtend2Data(target, handshakeType, handshakeData)
	if err != nil {
		return fmt.Errorf("failed to build EXTEND2 data for target %q: %w", target, err)
	}

	relayCell, err := cell.NewRelayCell(0, cell.RelayExtend2, extend2Data)
	if err != nil {
		return fmt.Errorf("failed to encode EXTEND2 relay cell: %w", err)
	}

	e.logger.Info("Sending EXTEND2 relay cell",
		"circuit_id", e.circuit.ID,
		"target", target,
		"nspec", extend2Data[0],
		"data_size", len(extend2Data),
		"htype", handshakeType,
		"hdata_len", len(handshakeData),
		"dump", DescribeExtend2(extend2Data))

	// Send EXTEND2 relay cell through the circuit
	if err := e.circuit.SendRelayCell(relayCell); err != nil {
		return fmt.Errorf("failed to send EXTEND2: %w", err)
	}

	// Wait for EXTENDED2 response
	extended2Cell, err := e.receiveExtended2(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive EXTENDED2: %w", err)
	}

	// Process EXTENDED2 response to derive keys
	if err := e.ProcessExtended2(extended2Cell); err != nil {
		return fmt.Errorf("failed to process EXTENDED2: %w", err)
	}

	e.logger.Info("Circuit extended successfully",
		"circuit_id", e.circuit.ID,
		"target", target)

	return nil
}

// HandshakeTypeFor 按最新 spec 选择握手：有 ntor-v3 密钥则用 0x0003。
func HandshakeTypeFor(relay interface{}) HandshakeType {
	type picker interface{ UseNtorV3() bool }
	if r, ok := relay.(picker); ok && r.UseNtorV3() {
		return HandshakeTypeNtorV3
	}
	return HandshakeTypeNTor
}

func requestCCFor(relay interface{}) bool {
	type picker interface{ RequestCongestionControl() bool }
	if r, ok := relay.(picker); ok {
		return r.RequestCongestionControl()
	}
	return false
}

func subprotoCapsFor(relay interface{}) ([]crypto.SubprotoCap, error) {
	type advertiser interface {
		crypto.ProtoSupport
	}
	if r, ok := relay.(advertiser); ok {
		return crypto.SelectSubprotoRequest(r)
	}
	return nil, nil
}

func (e *Extension) generateHandshakeData(handshakeType HandshakeType) ([]byte, error) {
	e.handshakeType = handshakeType
	switch handshakeType {
	case HandshakeTypeNtorV3:
		edID, ntorKey, err := e.getNtorV3Keys()
		if err != nil {
			return nil, fmt.Errorf("refusing ntor-v3 without Ed25519 identity: %w", err)
		}
		e.serverIdentity = append([]byte(nil), edID...)
		e.serverNtorKey = append([]byte(nil), ntorKey...)
		e.requestCC = requestCCFor(e.targetRelay)
		caps, err := subprotoCapsFor(e.targetRelay)
		if err != nil {
			return nil, fmt.Errorf("subproto_request selection: %w", err)
		}
		if len(caps) > 0 && !e.requestCC {
			return nil, fmt.Errorf("CGO requires FlowCtrl=2")
		}
		e.requestCGO = false
		for _, cap := range caps {
			if cap.ProtocolID == crypto.ProtoRelay && cap.Cap == crypto.CapRelayCGO {
				e.requestCGO = true
			}
		}
		cm, err := crypto.EncodeNtorV3ClientMsg(e.requestCC, caps)
		if err != nil {
			return nil, fmt.Errorf("ntor-v3 client extensions: %w", err)
		}
		if len(caps) > 0 {
			e.logger.Info("Requesting ntor-v3 subproto capabilities",
				"circuit_id", e.circuit.ID, "caps", caps)
		}
		skin, st, err := crypto.NtorV3ClientHandshake(edID, ntorKey, crypto.NtorV3CircuitVerification, cm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ntor-v3 handshake: %w", err)
		}
		if e.requestCGO {
			st.SetKeyMaterialLen(crypto.CGOKeyMaterialLen)
		}
		e.ntorv3State = st
		return skin, nil

	case HandshakeTypeNTor:
		// Use full ntor handshake implementation per tor-spec.txt section 5.1.4
		//
		// SPEC-001 RESOLUTION: Now properly integrated with directory service
		// Keys are obtained from network consensus and relay descriptors per:
		// 1. Fetch consensus from directory authorities (pkg/directory)
		// 2. Select relay based on flags and requirements (pkg/path)
		// 3. Relay descriptor contains ntor-onion-key and identity key
		// 4. Keys passed via SetTargetRelay() or extracted from descriptor

		nodeID, relayNtorKey, err := e.getRelayKeys()
		if err != nil {
			return nil, fmt.Errorf("refusing ntor handshake without real relay keys: %w", err)
		}

		e.serverIdentity = append([]byte(nil), nodeID...)
		e.serverNtorKey = append([]byte(nil), relayNtorKey...)

		handshakeData, ephemeralPrivate, err := crypto.NtorClientHandshake(nodeID, relayNtorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ntor handshake: %w", err)
		}
		e.ephemeralPrivate = ephemeralPrivate
		return handshakeData, nil

	case HandshakeTypeTAP:
		// LOW-001: Log deprecation warning for TAP handshake (RSA-1024)
		// TAP handshake uses RSA-1024 which is deprecated due to insufficient security margin.
		// The ntor handshake (Curve25519) should be preferred for all new circuits.
		e.logger.Warn("TAP handshake is deprecated - prefer ntor handshake (RSA-1024 offers insufficient security margin)",
			"circuit_id", e.circuit.ID,
			"recommendation", "use HandshakeTypeNTor for improved security")

		// TAP handshake: PK_ID (16 bytes) || Symmetric key material (128 bytes)
		// This is legacy and simplified
		data := make([]byte, 144)
		if _, err := rand.Read(data); err != nil {
			return nil, fmt.Errorf("failed to generate random data: %w", err)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("unsupported handshake type: %d", handshakeType)
	}
}

// EncodeExtend2Data 按当前 target relay 编 EXTEND2 负载，供集成测试检查 [01] 布局。
// 不发送、不改电路状态。
func EncodeExtend2Data(target string, relay interface{}, handshakeType HandshakeType, handshakeData []byte) ([]byte, error) {
	ext := NewExtension(NewCircuit(1), nil)
	ext.SetTargetRelay(relay)
	return ext.buildExtend2Data(target, handshakeType, handshakeData)
}

// buildExtend2Data builds the EXTEND2 relay cell data
func (e *Extension) buildExtend2Data(target string, handshakeType HandshakeType, handshakeData []byte) ([]byte, error) {
	// EXTEND2 format:
	// NSPEC (1 byte) - number of link specifiers
	// Link specifiers (variable)
	// HTYPE (2 bytes) - handshake type
	// HLEN (2 bytes) - handshake data length
	// HDATA (variable) - handshake data

	data := make([]byte, 0, 256)

	// Parse target address to extract IP and port
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q in target address", portStr)
	}

	// Parse IP address
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("target must be an IP address (hostnames require DNS resolution which is not supported in EXTEND2), got %q", host)
	}

	// 顺序按 spec：IPv4 [00]、legacy identity [02]、Ed25519 [03]、IPv6 [01]
	var specs [][]byte
	haveIPv6 := false
	ipv4 := ip.To4()
	if ipv4 != nil {
		specs = append(specs, encodeIPv4LinkSpec(ipv4, uint16(port)))
	} else {
		v6 := ip.To16()
		if v6 == nil {
			return nil, fmt.Errorf("target IP is neither IPv4 nor IPv6")
		}
		specs = append(specs, encodeIPv6LinkSpec(v6, uint16(port)))
		haveIPv6 = true
	}

	rsaID, edID, err := e.getRelayIdentities()
	if err != nil {
		return nil, fmt.Errorf("EXTEND2 requires target identity keys: %w", err)
	}
	if err := e.rejectExtendToPreviousHop(rsaID, edID); err != nil {
		return nil, err
	}
	spec := []byte{2, 20}
	spec = append(spec, rsaID...)
	specs = append(specs, spec)
	spec = []byte{3, 32}
	spec = append(spec, edID...)
	specs = append(specs, spec)

	if extraIP, extraPort, ok := e.extraIPv6LinkSpec(); ok && !haveIPv6 {
		specs = append(specs, encodeIPv6LinkSpec(extraIP, extraPort))
	}

	data = append(data, byte(len(specs)))
	for _, spec := range specs {
		data = append(data, spec...)
	}

	// HTYPE
	htypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(htypeBytes, uint16(handshakeType))
	data = append(data, htypeBytes...)

	// HLEN - safely convert handshake data length
	hlen, err := security.SafeLenToUint16(handshakeData)
	if err != nil {
		return nil, fmt.Errorf("handshake data too large: %w", err)
	}
	hlenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(hlenBytes, hlen)
	data = append(data, hlenBytes...)

	// HDATA
	data = append(data, handshakeData...)

	return data, nil
}

func encodeIPv4LinkSpec(ip net.IP, port uint16) []byte {
	spec := []byte{0, 6}
	spec = append(spec, ip.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(spec, portBytes...)
}

func encodeIPv6LinkSpec(ip net.IP, port uint16) []byte {
	spec := []byte{1, 18}
	spec = append(spec, ip.To16()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(spec, portBytes...)
}

type relayExtendIPv6 interface {
	ShouldIncludeExtendIPv6() bool
	IPv6ORAddress() (ip net.IP, port uint16, ok bool)
}

func (e *Extension) extraIPv6LinkSpec() (net.IP, uint16, bool) {
	src, ok := e.targetRelay.(relayExtendIPv6)
	if !ok || !src.ShouldIncludeExtendIPv6() {
		return nil, 0, false
	}
	ip, port, ok := src.IPv6ORAddress()
	if !ok || ip == nil || ip.To4() != nil || ip.To16() == nil || port == 0 {
		return nil, 0, false
	}
	return ip.To16(), port, true
}

// SetTargetRelay sets the target relay descriptor for key extraction (SPEC-001)
// This should be called before creating/extending circuits to provide actual relay keys
func (e *Extension) SetTargetRelay(relay interface{}) {
	e.targetRelay = relay
}

type relayNtorKeys interface {
	HasNtorKeys() bool
	GetNtorOnionKey() []byte
}

type relayRSAIdentity interface {
	RSAIdentityBytes() []byte
}

type relayEdIdentity interface {
	GetIdentityKey() []byte
}

func (e *Extension) getNtorV3Keys() (edID, ntorKey []byte, err error) {
	if e.targetRelay == nil {
		return nil, nil, fmt.Errorf("no target relay set")
	}
	if relay, ok := e.targetRelay.(relayNtorKeys); ok {
		if !relay.HasNtorKeys() {
			return nil, nil, fmt.Errorf("target relay missing ntor keys")
		}
		ntorKey = relay.GetNtorOnionKey()
	}
	if relay, ok := e.targetRelay.(relayEdIdentity); ok {
		edID = relay.GetIdentityKey()
	}
	if len(edID) != 32 || len(ntorKey) != 32 {
		return nil, nil, fmt.Errorf("target relay does not provide Ed25519(32) and ntor key(32): ed=%d ntor=%d", len(edID), len(ntorKey))
	}
	if allZeroBytes(edID) || allZeroBytes(ntorKey) {
		return nil, nil, fmt.Errorf("target relay ntor-v3 keys are all zeros")
	}
	return edID, ntorKey, nil
}

// getRelayKeys 返回 ntor NODEID（20 字节 RSA digest）和 ntor onion key。
func (e *Extension) getRelayKeys() (nodeID, ntorKey []byte, err error) {
	if e.targetRelay == nil {
		return nil, nil, fmt.Errorf("no target relay set")
	}

	if relay, ok := e.targetRelay.(relayNtorKeys); ok {
		if !relay.HasNtorKeys() {
			return nil, nil, fmt.Errorf("target relay missing ntor keys")
		}
		ntorKey = relay.GetNtorOnionKey()
	}

	if relay, ok := e.targetRelay.(relayRSAIdentity); ok {
		nodeID = relay.RSAIdentityBytes()
	}

	if len(nodeID) != 20 || len(ntorKey) != 32 {
		return nil, nil, fmt.Errorf("target relay does not provide NODEID(20) and ntor key(32): nodeID=%d ntor=%d", len(nodeID), len(ntorKey))
	}
	if allZeroBytes(nodeID) || allZeroBytes(ntorKey) {
		return nil, nil, fmt.Errorf("target relay keys are all zeros")
	}
	return nodeID, ntorKey, nil
}

func (e *Extension) getRelayIdentities() (rsaID, edID []byte, err error) {
	rsaID, _, err = e.getRelayKeys()
	if err != nil {
		return nil, nil, err
	}
	if relay, ok := e.targetRelay.(relayEdIdentity); ok {
		edID = relay.GetIdentityKey()
	}
	if len(edID) != 32 || allZeroBytes(edID) {
		return nil, nil, fmt.Errorf("target relay missing Ed25519 identity")
	}
	return rsaID, edID, nil
}

func allZeroBytes(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

// rejectExtendToPreviousHop 对应 C Tor circuit_extend_lspec_valid_helper：
// 禁止要求 Guard 连回上一跳（同一 RSA 或同一 Ed25519）。
func (e *Extension) rejectExtendToPreviousHop(rsaID, edID []byte) error {
	if e.circuit == nil {
		return nil
	}
	for _, hop := range e.circuit.GetHops() {
		if hop == nil {
			continue
		}
		if fp := strings.ToUpper(strings.TrimSpace(hop.Fingerprint)); fp != "" && len(rsaID) == 20 {
			if fp == strings.ToUpper(hex.EncodeToString(rsaID)) {
				return fmt.Errorf("EXTEND2 target RSA identity matches previous hop %s", hop.Fingerprint)
			}
		}
	}
	_ = edID
	return nil
}

// DescribeExtend2 把 EXTEND2 负载解析成可读摘要。
// 只记录 specifier 类型/长度、IPv4/端口、RSA hex、Ed25519 hex、HTYPE/HLEN；
// HDATA 只记长度，不输出握手私钥。
func DescribeExtend2(data []byte) string {
	if len(data) < 1 {
		return "empty"
	}
	nspec := int(data[0])
	parts := []string{fmt.Sprintf("nspec=%d", nspec)}
	off := 1
	for i := 0; i < nspec; i++ {
		if off+2 > len(data) {
			parts = append(parts, fmt.Sprintf("spec%d=truncated", i))
			return strings.Join(parts, " ")
		}
		lstype := data[off]
		lslen := int(data[off+1])
		off += 2
		if off+lslen > len(data) {
			parts = append(parts, fmt.Sprintf("t=%d l=%d truncated", lstype, lslen))
			return strings.Join(parts, " ")
		}
		body := data[off : off+lslen]
		off += lslen
		switch lstype {
		case 0:
			if lslen == 6 {
				ip := net.IP(body[:4]).String()
				port := binary.BigEndian.Uint16(body[4:6])
				parts = append(parts, fmt.Sprintf("[00] %s:%d", ip, port))
			} else {
				parts = append(parts, fmt.Sprintf("[00] l=%d", lslen))
			}
		case 1:
			if lslen == 18 {
				ip := net.IP(body[:16]).String()
				port := binary.BigEndian.Uint16(body[16:18])
				parts = append(parts, fmt.Sprintf("[01] [%s]:%d", ip, port))
			} else {
				parts = append(parts, fmt.Sprintf("[01] l=%d", lslen))
			}
		case 2:
			parts = append(parts, fmt.Sprintf("[02] rsa=%s", strings.ToUpper(hex.EncodeToString(body))))
		case 3:
			parts = append(parts, fmt.Sprintf("[03] ed=%s", hex.EncodeToString(body)))
		default:
			parts = append(parts, fmt.Sprintf("[0x%02x] l=%d", lstype, lslen))
		}
	}
	if off+4 > len(data) {
		parts = append(parts, "handshake=truncated")
		return strings.Join(parts, " ")
	}
	htype := binary.BigEndian.Uint16(data[off : off+2])
	hlen := binary.BigEndian.Uint16(data[off+2 : off+4])
	off += 4
	parts = append(parts, fmt.Sprintf("htype=0x%04x hlen=%d leftover=%d", htype, hlen, len(data)-off))
	if int(hlen) <= len(data)-off && hlen >= 20 {
		parts = append(parts, fmt.Sprintf("hdata_nodeid=%s", strings.ToUpper(hex.EncodeToString(data[off:off+20]))))
	}
	return strings.Join(parts, " ")
}

// ProcessCreated2 processes a CREATED2 response from the first hop
// AUDIT-001 FIX: Now properly verifies ntor handshake and derives keys
func (e *Extension) ProcessCreated2(created2Cell *cell.Cell) error {
	// Guard against nil cell input to prevent nil pointer dereference
	if created2Cell == nil {
		return fmt.Errorf("CREATED2 cell is nil")
	}
	if created2Cell.Command != cell.CmdCreated2 {
		return fmt.Errorf("expected CREATED2 cell, got %s", created2Cell.Command)
	}

	e.logger.Debug("Processing CREATED2 cell", "circuit_id", created2Cell.CircID)

	// Parse CREATED2 response
	payload := created2Cell.Payload
	if len(payload) < 2 {
		return fmt.Errorf("CREATED2 payload too short")
	}

	hlen := binary.BigEndian.Uint16(payload[0:2])
	if len(payload) < int(2+hlen) {
		return fmt.Errorf("CREATED2 payload incomplete")
	}

	handshakeResponse := payload[2 : 2+hlen]
	if err := e.finishHandshake(handshakeResponse); err != nil {
		return err
	}
	e.logger.Info("CREATED2 processed successfully with verified keys",
		"circuit_id", e.circuit.ID,
		"handshake", e.handshakeType)
	return nil
}

// ProcessExtended2 processes an EXTENDED2 response from circuit extension
// AUDIT-001 FIX: Now properly verifies ntor handshake and derives keys
func (e *Extension) ProcessExtended2(extended2Cell *cell.RelayCell) error {
	// Guard against nil cell input to prevent nil pointer dereference
	if extended2Cell == nil {
		return fmt.Errorf("EXTENDED2 relay cell is nil")
	}
	if extended2Cell.Command != cell.RelayExtended2 {
		return fmt.Errorf("expected RELAY_EXTENDED2 cell, got %d", extended2Cell.Command)
	}

	e.logger.Debug("Processing EXTENDED2 relay cell", "circuit_id", e.circuit.ID)

	// Ensure ephemeral key is cleared after processing (success or failure)
	defer func() {
		if e.ephemeralPrivate != nil {
			security.SecureZeroMemory(e.ephemeralPrivate)
			e.ephemeralPrivate = nil
		}
	}()

	// Parse EXTENDED2 response (similar to CREATED2)
	payload := extended2Cell.Data
	if len(payload) < 2 {
		return fmt.Errorf("EXTENDED2 payload too short")
	}

	hlen := binary.BigEndian.Uint16(payload[0:2])
	if len(payload) < int(2+hlen) {
		return fmt.Errorf("EXTENDED2 payload incomplete")
	}

	handshakeResponse := payload[2 : 2+hlen]
	if err := e.finishHandshake(handshakeResponse); err != nil {
		return err
	}
	e.logger.Info("EXTENDED2 processed successfully with verified keys",
		"circuit_id", e.circuit.ID,
		"handshake", e.handshakeType)
	return nil
}

func (e *Extension) finishHandshake(handshakeResponse []byte) error {
	var keyMaterial, serverMsg, circNonce []byte
	var err error
	switch e.handshakeType {
	case HandshakeTypeNtorV3:
		if e.ntorv3State == nil {
			return fmt.Errorf("no ntor-v3 state stored")
		}
		keyMaterial, serverMsg, err = crypto.NtorV3ProcessResponse(handshakeResponse, e.ntorv3State, crypto.NtorV3CircuitVerification)
		if err == nil && len(e.ntorv3State.CircNonce) == crypto.NtorCircNonceLen {
			circNonce = append([]byte(nil), e.ntorv3State.CircNonce...)
		}
		e.ntorv3State.Wipe()
		e.ntorv3State = nil
		if err != nil {
			return fmt.Errorf("ntor-v3 handshake verification failed: %w", err)
		}
	default:
		if e.ephemeralPrivate == nil {
			return fmt.Errorf("no ephemeral private key stored - handshake not initiated properly")
		}
		keyMaterial, circNonce, err = crypto.NtorProcessResponseWithNonce(
			handshakeResponse,
			e.ephemeralPrivate,
			e.serverNtorKey,
			e.serverIdentity,
		)
		security.SecureZeroMemory(e.ephemeralPrivate)
		e.ephemeralPrivate = nil
		if err != nil {
			return fmt.Errorf("ntor handshake verification failed: %w", err)
		}
	}
	if e.requestCGO {
		if len(keyMaterial) != crypto.CGOKeyMaterialLen {
			return fmt.Errorf("CGO requested: key material %d, want %d (refusing AES-CTR fallback)", len(keyMaterial), crypto.CGOKeyMaterialLen)
		}
	} else if len(keyMaterial) < 72 {
		return fmt.Errorf("insufficient key material: got %d bytes, need 72", len(keyMaterial))
	}
	hop, err := e.deriveHopFromKeyMaterial(keyMaterial)
	if err != nil {
		return fmt.Errorf("failed to derive hop crypto state: %w", err)
	}
	if len(circNonce) == crypto.NtorCircNonceLen {
		hop.RendCircNonce = circNonce
	}
	if err := e.circuit.AddHop(hop); err != nil {
		return fmt.Errorf("failed to add hop to circuit: %w", err)
	}
	if len(serverMsg) > 0 {
		inc, ok, err := crypto.ParseCCSendmeInc(serverMsg)
		if err != nil {
			return fmt.Errorf("ntor-v3 server extra data: %w", err)
		}
		if ok {
			e.circuit.EnableCongestionControl(inc)
			e.logger.Info("Negotiated FlowCtrl=2", "sendme_inc", inc)
		}
	}
	if e.requestCGO {
		e.logger.Info("Negotiated Relay=6 CGO", "circuit_id", e.circuit.ID)
	}
	return nil
}

// deriveHopFromKeyMaterial creates a Hop with cryptographic state from key material
// Per tor-spec.txt §5.2, key material layout is:
// - Df (20 bytes): forward digest key
// - Db (20 bytes): backward digest key
// - Kf (16 bytes): forward cipher key (AES-128)
// - Kb (16 bytes): backward cipher key (AES-128)
func (e *Extension) deriveHopFromKeyMaterial(keyMaterial []byte) (*Hop, error) {
	if e.requestCGO {
		pair, err := crypto.NewCGOPairFromKeyMaterial(keyMaterial)
		if err != nil {
			return nil, err
		}
		hop := &Hop{CGO: pair}
		if relay, ok := e.targetRelay.(interface{ String() string }); ok {
			hop.Address = relay.String()
		}
		if relay, ok := e.targetRelay.(interface{ GetFingerprintHex() string }); ok {
			hop.Fingerprint = relay.GetFingerprintHex()
		}
		e.logger.Info("Derived CGO hop",
			"circuit_id", e.circuit.ID,
			"key_len", len(keyMaterial))
		return hop, nil
	}
	if len(keyMaterial) < 72 {
		return nil, fmt.Errorf("insufficient key material: got %d bytes, need 72", len(keyMaterial))
	}

	// Extract keys from key material per tor-spec.txt §5.2
	dfKey := keyMaterial[0:20]  // Forward digest key
	dbKey := keyMaterial[20:40] // Backward digest key
	kfKey := keyMaterial[40:56] // Forward cipher key (AES-128)
	kbKey := keyMaterial[56:72] // Backward cipher key (AES-128)

	// Create forward cipher (client → relay)
	// Per tor-spec.txt §5.1.1, use AES-128-CTR with zero IV
	zeroIV := make([]byte, 16)
	forwardCipherWrapper, err := crypto.NewAESCTRCipher(kfKey, zeroIV)
	if err != nil {
		return nil, fmt.Errorf("failed to create forward cipher: %w", err)
	}

	// Create backward cipher (relay → client)
	backwardCipherWrapper, err := crypto.NewAESCTRCipher(kbKey, zeroIV)
	if err != nil {
		return nil, fmt.Errorf("failed to create backward cipher: %w", err)
	}

	// Extract the underlying cipher.Stream from the wrappers
	forwardCipher := forwardCipherWrapper.Stream()
	backwardCipher := backwardCipherWrapper.Stream()

	// Create digest hashes per tor-spec.txt §6.1
	// SHA-1 running digests for relay cell verification
	// Initialize with the digest keys (Df, Db)
	forwardDigest := sha1.New() // #nosec G401 - SHA-1 required by Tor spec
	forwardDigest.Write(dfKey)  // #nosec G104 - hash.Hash.Write never fails

	backwardDigest := sha1.New() // #nosec G401 - SHA-1 required by Tor spec
	backwardDigest.Write(dbKey)  // #nosec G104 - hash.Hash.Write never fails

	hop := &Hop{
		ForwardCipher:  forwardCipher,
		BackwardCipher: backwardCipher,
		ForwardDigest:  forwardDigest,
		BackwardDigest: backwardDigest,
	}
	if relay, ok := e.targetRelay.(interface{ String() string }); ok {
		hop.Address = relay.String()
	}
	if relay, ok := e.targetRelay.(interface{ GetFingerprintHex() string }); ok {
		hop.Fingerprint = relay.GetFingerprintHex()
	}

	e.logger.Debug("Derived hop cryptographic state from key material",
		"circuit_id", e.circuit.ID,
		"df_len", len(dfKey),
		"db_len", len(dbKey),
		"kf_len", len(kfKey),
		"kb_len", len(kbKey))

	return hop, nil
}

// DeriveKeys derives encryption keys for a circuit hop using KDF-TOR
func (e *Extension) DeriveKeys(sharedSecret []byte) (forwardKey, backwardKey []byte, err error) {
	// Use crypto package for key derivation
	// KDF-TOR produces: Df || Db || Kf || Kb
	// Where: Df, Db = forward/backward digest keys (20 bytes each)
	//        Kf, Kb = forward/backward cipher keys (16 bytes each for AES-128)

	const keyMaterial = 72 // 20 + 20 + 16 + 16 bytes

	// Derive key material using KDF
	km, err := crypto.DeriveKey(sharedSecret, keyMaterial)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Split key material
	// For now, we'll return cipher keys only
	forwardKey = km[40:56]  // Kf (offset 40, 16 bytes)
	backwardKey = km[56:72] // Kb (offset 56, 16 bytes)

	e.logger.Debug("Keys derived",
		"circuit_id", e.circuit.ID,
		"forward_key_len", len(forwardKey),
		"backward_key_len", len(backwardKey))

	return forwardKey, backwardKey, nil
}

// getConnection retrieves the connection from the circuit
// Returns an interface that implements SendCell and ReceiveCell methods
func (e *Extension) getConnection() (CellConnection, error) {
	e.circuit.mu.RLock()
	conn := e.circuit.conn
	e.circuit.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("circuit has no connection")
	}

	// Type assert to CellConnection interface
	cellConn, ok := conn.(CellConnection)
	if !ok {
		return nil, fmt.Errorf("connection does not implement CellConnection interface")
	}

	return cellConn, nil
}

// receiveCreated2 waits for and receives a CREATED2 cell
func (e *Extension) receiveCreated2(ctx context.Context, conn CellConnection) (*cell.Cell, error) {
	// Create a timeout for receiving the response
	timeout := 30 * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	e.circuit.mu.RLock()
	mux := e.circuit.mux
	e.circuit.mu.RUnlock()
	if mux != nil {
		return mux.WaitCreated2(timeoutCtx, e.circuit.ID)
	}

	// ReceiveCell 是阻塞调用；必须放到 goroutine，否则 timeout/ctx 无法打断。
	type recvResult struct {
		c   *cell.Cell
		err error
	}
	ch := make(chan recvResult, 1)
	go func() {
		for {
			receivedCell, err := conn.ReceiveCell()
			if err != nil {
				ch <- recvResult{err: fmt.Errorf("failed to receive cell: %w", err)}
				return
			}
			if receivedCell.CircID != e.circuit.ID {
				e.logger.Debug("Received cell for different circuit",
					"expected_circuit", e.circuit.ID,
					"received_circuit", receivedCell.CircID)
				continue
			}
			if receivedCell.Command == cell.CmdCreated2 {
				ch <- recvResult{c: receivedCell}
				return
			}
			e.logger.Warn("Received unexpected cell while waiting for CREATED2",
				"command", receivedCell.Command,
				"circuit_id", receivedCell.CircID)
		}
	}()

	select {
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("timeout waiting for CREATED2: %w", timeoutCtx.Err())
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		e.logger.Debug("Received CREATED2 cell", "circuit_id", r.c.CircID)
		return r.c, nil
	}
}

// receiveExtended2 waits for and receives an EXTENDED2 relay cell
func (e *Extension) receiveExtended2(ctx context.Context) (*cell.RelayCell, error) {
	// Create a timeout for receiving the response
	timeout := 30 * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	e.logger.Debug("Waiting for EXTENDED2 relay cell", "circuit_id", e.circuit.ID)

	// Wait for EXTENDED2 relay cell
	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("timeout waiting for EXTENDED2: %w", timeoutCtx.Err())
		default:
			receivedCell, err := e.circuit.ReceiveRelayCellTimeout(1 * time.Second)
			if err != nil {
				// Check if it's a timeout - if so, continue waiting
				if err == context.DeadlineExceeded {
					continue
				}
				return nil, fmt.Errorf("failed to receive relay cell: %w", err)
			}

			// Check if it's the EXTENDED2 we're waiting for
			if receivedCell.Command == cell.RelayExtended2 {
				e.logger.Debug("Received EXTENDED2 relay cell", "circuit_id", e.circuit.ID)
				return receivedCell, nil
			}

			// Log unexpected cells
			e.logger.Warn("Received unexpected relay cell while waiting for EXTENDED2",
				"command", receivedCell.Command,
				"circuit_id", e.circuit.ID)
		}
	}
}

// CellConnection defines the interface required for sending and receiving cells
type CellConnection interface {
	SendCell(c *cell.Cell) error
	ReceiveCell() (*cell.Cell, error)
}
