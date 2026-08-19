package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// mockConn is a mock connection for testing
type mockConn struct {
	mu        sync.Mutex
	readData  []byte
	readPos   int
	writeData []byte
	closed    bool
}

func newMockConn() *mockConn {
	return &mockConn{
		readData: make([]byte, 0),
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321}
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockConn) addReadData(data []byte) {
	m.readData = append(m.readData, data...)
}

func (m *mockConn) getWrittenCells(circIDLen int) ([]*cell.Cell, error) {
	m.mu.Lock()
	data := append([]byte(nil), m.writeData...)
	m.mu.Unlock()

	r := bytes.NewReader(data)
	var cells []*cell.Cell
	for r.Len() > 0 {
		c, err := cell.DecodeCellLink(r, circIDLen)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return cells, err
		}
		cells = append(cells, c)
	}
	return cells, nil
}

// inboundVersionsWire2 是权威/C Tor 握手线上的 VERSIONS：CIRCID_LEN(v_in=0)=2。
// 00 00 | 07 | 00 06 | 00 03 00 04 00 05
func inboundVersionsWire2() []byte {
	return []byte{
		0x00, 0x00,
		byte(cell.CmdVersions),
		0x00, 0x06,
		0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
	}
}

func TestNewLinkProtocolHandler(t *testing.T) {
	keys := generateTestRelayKeys(t)
	log := logger.NewDefault()

	handler := NewLinkProtocolHandler(keys, log)
	if handler == nil {
		t.Fatal("NewLinkProtocolHandler returned nil")
	}
	if handler.keys != keys {
		t.Error("Keys not set correctly")
	}
	if handler.logger == nil {
		t.Error("Logger should not be nil")
	}

	// Test with nil logger (should create default)
	handler2 := NewLinkProtocolHandler(keys, nil)
	if handler2.logger == nil {
		t.Error("Handler should create default logger if nil provided")
	}
}

func TestSelectVersion(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	tests := []struct {
		name            string
		clientVersions  []int
		expectedVersion int
	}{
		{
			name:            "Client supports v5",
			clientVersions:  []int{3, 4, 5},
			expectedVersion: 5,
		},
		{
			name:            "Client supports only v4",
			clientVersions:  []int{4},
			expectedVersion: 4,
		},
		{
			name:            "Client supports only v3",
			clientVersions:  []int{3},
			expectedVersion: 3,
		},
		{
			name:            "Client supports v2 and v3",
			clientVersions:  []int{2, 3},
			expectedVersion: 3,
		},
		{
			name:            "No compatible version",
			clientVersions:  []int{1, 2},
			expectedVersion: 0,
		},
		{
			name:            "Client supports higher version",
			clientVersions:  []int{5, 6, 7},
			expectedVersion: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := handler.selectVersion(tt.clientVersions)
			if version != tt.expectedVersion {
				t.Errorf("selectVersion(%v) = %d, want %d",
					tt.clientVersions, version, tt.expectedVersion)
			}
		})
	}
}

func TestReceiveVersions(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	conn := newMockConn()
	conn.addReadData(inboundVersionsWire2())

	ctx := context.Background()
	receivedVersions, err := handler.receiveVersions(ctx, conn)
	if err != nil {
		t.Fatalf("receiveVersions failed: %v", err)
	}

	if len(receivedVersions) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(receivedVersions))
	}
	expectedVersions := []int{3, 4, 5}
	for i, v := range receivedVersions {
		if v != expectedVersions[i] {
			t.Errorf("Version[%d] = %d, want %d", i, v, expectedVersions[i])
		}
	}
}

// TestInboundVersionsCircIDWidthBeforeNegotiation 锁定入站握手根因：
// 权威 VERSIONS 为 2 字节 CircID（00 00 07 …）。协商前按 4 字节解析会得到
// CREATED_FAST（长度字段低位 0x06）；修复后入站路径必须识别为 VERSIONS。
func TestInboundVersionsCircIDWidthBeforeNegotiation(t *testing.T) {
	wire := inboundVersionsWire2()
	if len(wire) < 5 {
		t.Fatalf("VERSIONS wire too short: %d", len(wire))
	}
	if wire[0] != 0x00 || wire[1] != 0x00 || wire[2] != byte(cell.CmdVersions) {
		t.Fatalf("VERSIONS wire prefix = %x, want 00 00 07", wire[:3])
	}

	encoded := cell.NewCell(0, cell.CmdVersions)
	encoded.Payload = []byte{0x00, 0x03, 0x00, 0x04, 0x00, 0x05}
	var encBuf bytes.Buffer
	if err := encoded.EncodeLink(&encBuf, 2); err != nil {
		t.Fatalf("EncodeLink(2): %v", err)
	}
	if !bytes.Equal(encBuf.Bytes(), wire) {
		t.Fatalf("EncodeLink(2) = %x, want hardcoded %x", encBuf.Bytes(), wire)
	}

	// 协商前按 4 字节 CircID 读头：第 5 字节是变长长度低位 0x06 → CREATED_FAST
	oldCmd := cell.Command(wire[4])
	if oldCmd != cell.CmdCreatedFast {
		t.Fatalf("4-byte header parse must yield CREATED_FAST, got %s (byte %02x)", oldCmd, wire[4])
	}

	padded := make([]byte, cell.CellLen)
	copy(padded, wire)
	wrong, err := cell.DecodeCellLink(bytes.NewReader(padded), 4)
	if err != nil {
		t.Fatalf("4-byte decode of padded VERSIONS wire failed: %v", err)
	}
	if wrong.Command != cell.CmdCreatedFast {
		t.Fatalf("4-byte DecodeCellLink must yield CREATED_FAST, got %s", wrong.Command)
	}

	right, err := cell.DecodeCellLink(bytes.NewReader(wire), 2)
	if err != nil {
		t.Fatalf("2-byte decode failed: %v", err)
	}
	if right.Command != cell.CmdVersions || right.CircID != 0 {
		t.Fatalf("2-byte decode: cmd=%s circ=%d, want VERSIONS/0", right.Command, right.CircID)
	}

	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)
	conn := newMockConn()
	conn.addReadData(wire)

	got, err := handler.receiveVersions(context.Background(), conn)
	if err != nil {
		t.Fatalf("receiveVersions after fix failed: %v", err)
	}
	want := []int{3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("versions = %v, want %v", got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("versions = %v, want %v", got, want)
		}
	}
}

func TestReceiveVersionsInvalidCell(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	// Build NETINFO cell instead of VERSIONS
	netinfoCell := cell.NewCell(0, cell.CmdNetinfo)
	netinfoCell.Payload = make([]byte, 20)
	var buf bytes.Buffer
	err := netinfoCell.Encode(&buf)
	if err != nil {
		t.Fatalf("Failed to encode NETINFO cell: %v", err)
	}
	cellData := buf.Bytes()

	conn := newMockConn()
	conn.addReadData(cellData)

	ctx := context.Background()
	_, err = handler.receiveVersions(ctx, conn)
	if err == nil {
		t.Error("receiveVersions should fail with non-VERSIONS cell")
	}
}

func TestSendVersions(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	conn := newMockConn()
	err := handler.sendVersions(conn)
	if err != nil {
		t.Fatalf("sendVersions failed: %v", err)
	}

	conn.mu.Lock()
	written := append([]byte(nil), conn.writeData...)
	conn.mu.Unlock()
	if len(written) < 3 || written[0] != 0x00 || written[1] != 0x00 || written[2] != byte(cell.CmdVersions) {
		t.Fatalf("sendVersions wire prefix = %x, want 00 00 07", written)
	}

	// Parse written cell（VERSIONS 仍是 2 字节 CircID）
	cells, err := conn.getWrittenCells(2)
	if err != nil {
		t.Fatalf("Failed to parse written cells: %v", err)
	}

	if len(cells) != 1 {
		t.Fatalf("Expected 1 cell, got %d", len(cells))
	}

	c := cells[0]
	if c.Command != cell.CmdVersions {
		t.Errorf("Expected VERSIONS cell, got %s", c.Command)
	}

	// Parse versions
	if len(c.Payload)%2 != 0 {
		t.Fatalf("Invalid payload length: %d", len(c.Payload))
	}

	var versions []int
	for i := 0; i < len(c.Payload); i += 2 {
		version := int(binary.BigEndian.Uint16(c.Payload[i : i+2]))
		versions = append(versions, version)
	}

	expectedVersions := []int{3, 4, 5}
	if len(versions) != len(expectedVersions) {
		t.Errorf("Expected %d versions, got %d", len(expectedVersions), len(versions))
	}
	for i, v := range versions {
		if v != expectedVersions[i] {
			t.Errorf("Version[%d] = %d, want %d", i, v, expectedVersions[i])
		}
	}
}

func TestSendCerts(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)
	handler.setCircIDLen(4) // CERTS 在 VERSIONS 协商之后

	conn := newMockConn()
	err := handler.sendCerts(conn)
	if err != nil {
		t.Fatalf("sendCerts failed: %v", err)
	}

	// Parse written cell
	cells, err := conn.getWrittenCells(4)
	if err != nil {
		t.Fatalf("Failed to parse written cells: %v", err)
	}

	if len(cells) != 1 {
		t.Fatalf("Expected 1 cell, got %d", len(cells))
	}

	c := cells[0]
	if c.Command != cell.CmdCerts {
		t.Errorf("Expected CERTS cell, got %s", c.Command)
	}

	// Parse CERTS payload
	if len(c.Payload) < 1 {
		t.Fatal("CERTS payload too short")
	}

	numCerts := int(c.Payload[0])
	if numCerts < 1 {
		t.Error("Expected at least 1 certificate")
	}

	t.Logf("CERTS cell contains %d certificates", numCerts)
}

func TestSendNetinfo(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)
	handler.setCircIDLen(4) // NETINFO 在 VERSIONS 协商之后

	conn := newMockConn()
	err := handler.sendNetinfo(conn)
	if err != nil {
		t.Fatalf("sendNetinfo failed: %v", err)
	}

	// Parse written cell
	cells, err := conn.getWrittenCells(4)
	if err != nil {
		t.Fatalf("Failed to parse written cells: %v", err)
	}

	if len(cells) != 1 {
		t.Fatalf("Expected 1 cell, got %d", len(cells))
	}

	c := cells[0]
	if c.Command != cell.CmdNetinfo {
		t.Errorf("Expected NETINFO cell, got %s", c.Command)
	}

	// Validate payload structure
	if len(c.Payload) < 10 {
		t.Errorf("NETINFO payload too short: %d bytes", len(c.Payload))
	}

	// Check timestamp (first 4 bytes)
	timestamp := binary.BigEndian.Uint32(c.Payload[0:4])
	if timestamp == 0 {
		t.Log("Warning: timestamp is 0 (may be expected in some cases)")
	}
}

func TestReceiveNetinfo(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)
	handler.setCircIDLen(4) // NETINFO 在 VERSIONS 协商之后

	// Build NETINFO cell
	var payload []byte
	// Timestamp
	timestamp := uint32(time.Now().Unix())
	payload = append(payload,
		byte(timestamp>>24), byte(timestamp>>16),
		byte(timestamp>>8), byte(timestamp))
	// OtherAddress (IPv4)
	payload = append(payload, 0x04, 4, 127, 0, 0, 1)
	// NumAddresses
	payload = append(payload, 0)

	netinfoCell := cell.NewCell(0, cell.CmdNetinfo)
	netinfoCell.Payload = payload
	var buf bytes.Buffer
	err := netinfoCell.Encode(&buf)
	if err != nil {
		t.Fatalf("Failed to encode NETINFO cell: %v", err)
	}
	cellData := buf.Bytes()

	conn := newMockConn()
	conn.addReadData(cellData)

	ctx := context.Background()
	err = handler.receiveNetinfo(ctx, conn)
	if err != nil {
		t.Fatalf("receiveNetinfo failed: %v", err)
	}
}

func TestBuildEd25519SigningCert(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	cert, err := handler.buildEd25519SigningCert()
	if err != nil {
		t.Fatalf("buildEd25519SigningCert failed: %v", err)
	}

	// Validate cert structure
	// Version (1) + CertType (1) + Expiration (4) + CertKeyType (1) +
	// CertifiedKey (32) + NumExtensions (1) + Signature (64) = 104 bytes minimum
	if len(cert) < 104 {
		t.Errorf("Expected cert length >= 104, got %d", len(cert))
	}

	// Validate version
	if cert[0] != 0x01 {
		t.Errorf("Expected version 1, got %d", cert[0])
	}

	// Validate cert type
	if cert[1] != 0x04 {
		t.Errorf("Expected cert type 4, got %d", cert[1])
	}

	// Validate number of extensions (at offset 38: 1+1+4+1+32-1 = 38)
	numExtensionsOffset := 1 + 1 + 4 + 1 + 32 // version + certType + expiration + certKeyType + certifiedKey
	numExtensions := cert[numExtensionsOffset]
	if numExtensions != 0x00 {
		t.Errorf("Expected 0 extensions, got %d", numExtensions)
	}

	// Validate signature (last 64 bytes after extensions section)
	signatureOffset := numExtensionsOffset + 1 // after numExtensions byte
	signature := cert[signatureOffset : signatureOffset+64]
	certBody := cert[0:signatureOffset]

	if !ed25519.Verify(keys.Ed25519Public, certBody, signature) {
		t.Error("Ed25519 certificate signature verification failed")
	}
}

func generateTestRelayKeys(t *testing.T) *RelayKeys {
	t.Helper()

	// Generate Ed25519 keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create minimal keys
	keys := &RelayKeys{
		Ed25519Public:  pub,
		Ed25519Private: priv,
		TLSCert:        make([]byte, 100), // Dummy cert
	}

	return keys
}

func TestHandleConnectionTimeout(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Create mock connection that doesn't send data
	conn := newMockConn()

	// This should timeout
	_, err := handler.HandleConnection(ctx, conn)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestHandleConnectionSwitchesCircIDAfterVersions(t *testing.T) {
	keys := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(keys, nil)

	netinfoCell := cell.NewCell(0, cell.CmdNetinfo)
	netinfoCell.Payload = []byte{
		0x00, 0x00, 0x00, 0x01,
		0x04, 4, 127, 0, 0, 1,
		0,
	}
	var netinfoBuf bytes.Buffer
	if err := netinfoCell.EncodeLink(&netinfoBuf, 4); err != nil {
		t.Fatalf("encode NETINFO: %v", err)
	}

	conn := newMockConn()
	conn.addReadData(inboundVersionsWire2())
	conn.addReadData(netinfoBuf.Bytes())

	orConn, err := handler.HandleConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("HandleConnection failed: %v", err)
	}
	if orConn.negotiatedVersion != 5 {
		t.Fatalf("negotiated version = %d, want 5", orConn.negotiatedVersion)
	}
	if orConn.circIDLen != 4 {
		t.Fatalf("post-handshake circIDLen = %d, want 4", orConn.circIDLen)
	}

	conn.mu.Lock()
	written := append([]byte(nil), conn.writeData...)
	conn.mu.Unlock()
	if len(written) < 3 || written[0] != 0x00 || written[1] != 0x00 || written[2] != byte(cell.CmdVersions) {
		t.Fatalf("server VERSIONS prefix = %x, want 00 00 07", written)
	}
}
