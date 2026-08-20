package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/protocol"
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

	// 协商前按 2 字节 CircID 读；必须 EncodeLink(..., 2)，否则测到的是解码宽度错误而非命令错误
	netinfoCell := cell.NewCell(0, cell.CmdNetinfo)
	netinfoCell.Payload = make([]byte, 20)
	var buf bytes.Buffer
	err := netinfoCell.EncodeLink(&buf, 2)
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

	cells, err := conn.getWrittenCells(4)
	if err != nil {
		t.Fatalf("Failed to parse written cells: %v", err)
	}
	if len(cells) != 1 {
		t.Fatalf("Expected 1 cell, got %d", len(cells))
	}
	c := cells[0]
	if c.Command != cell.CmdCerts {
		t.Fatalf("Expected CERTS cell, got %s", c.Command)
	}

	parsed, err := protocol.ParseCERTSCell(c)
	if err != nil {
		t.Fatalf("ParseCERTSCell: %v", err)
	}
	wantTypes := []protocol.CertType{
		protocol.CertTypeTLSLink,
		protocol.CertTypeRSAID,
		protocol.CertTypeEd25519Signing,
		protocol.CertTypeEd25519TLSLink,
		protocol.CertTypeEd25519Identity,
	}
	if len(parsed.Certificates) != len(wantTypes) {
		t.Fatalf("num certs = %d, want %d", len(parsed.Certificates), len(wantTypes))
	}
	for i, wt := range wantTypes {
		if parsed.Certificates[i].CertType != wt {
			t.Fatalf("cert[%d] type = %s, want %s", i, parsed.Certificates[i].CertType, wt)
		}
	}
	if err := parsed.ValidateSignatures(); err != nil {
		t.Fatalf("ValidateSignatures: %v", err)
	}
	if err := parsed.ValidateExpiration(); err != nil {
		t.Fatalf("ValidateExpiration: %v", err)
	}

	type4 := parsed.FindCertificate(protocol.CertTypeEd25519Signing)
	if type4 == nil || type4.Ed25519Cert == nil {
		t.Fatal("missing type 4")
	}
	if type4.Ed25519Cert.SignedWithEd25519Key() == nil {
		t.Fatal("type 4 missing signed-with-ed25519-key extension")
	}
	if bytes.Equal(type4.Ed25519Cert.CertifiedKey, keys.Ed25519Public) {
		t.Fatal("type 4 certified key must be medium-term signing key, not identity")
	}

	type5 := parsed.FindCertificate(protocol.CertTypeEd25519TLSLink)
	if type5 == nil || type5.Ed25519Cert == nil {
		t.Fatal("missing type 5")
	}
	if type5.Ed25519Cert.CertKeyType != protocol.CertKeyTypeSHA256OfX509 {
		t.Fatalf("type 5 key type = %d, want SHA256_OF_X509", type5.Ed25519Cert.CertKeyType)
	}
	id, err := parsed.Ed25519IdentityKey()
	if err != nil {
		t.Fatalf("Ed25519IdentityKey: %v", err)
	}
	if !bytes.Equal(id, keys.Ed25519Public) {
		t.Fatal("type 7 Ed25519 identity does not match relay key")
	}
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
	handler.setCircIDLen(4)
	err = handler.receiveInitiatorFinish(ctx, conn, nil)
	if err != nil {
		t.Fatalf("receiveInitiatorFinish failed: %v", err)
	}
}

func TestBuildIdentitySigningCert(t *testing.T) {
	keys := generateTestRelayKeys(t)
	signPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	raw, err := buildIdentitySigningCert(keys.Ed25519Private, signPub, expires)
	if err != nil {
		t.Fatalf("buildIdentitySigningCert: %v", err)
	}
	parsed, err := protocol.ParseEd25519Certificate(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.CertType != uint8(protocol.CertTypeEd25519Signing) {
		t.Fatalf("cert type = %d, want 4", parsed.CertType)
	}
	if !bytes.Equal(parsed.CertifiedKey, signPub) {
		t.Fatal("certified key is not the signing public key")
	}
	if !bytes.Equal(parsed.SignedWithEd25519Key(), keys.Ed25519Public) {
		t.Fatal("signed-with-ed25519-key must be identity")
	}
	if err := parsed.VerifySignature(keys.Ed25519Public); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestBuildTLSLinkCert(t *testing.T) {
	keys := generateTestRelayKeys(t)
	_, signPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	raw, err := buildTLSLinkCert(keys.TLSCert, signPriv, expires)
	if err != nil {
		t.Fatalf("buildTLSLinkCert: %v", err)
	}
	parsed, err := protocol.ParseEd25519Certificate(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.CertType != uint8(protocol.CertTypeEd25519TLSLink) {
		t.Fatalf("cert type = %d, want 5", parsed.CertType)
	}
	if parsed.CertKeyType != protocol.CertKeyTypeSHA256OfX509 {
		t.Fatalf("key type = %d, want 3", parsed.CertKeyType)
	}
	sum := sha256.Sum256(keys.TLSCert)
	if !bytes.Equal(parsed.CertifiedKey, sum[:]) {
		t.Fatal("type 5 certified key is not SHA-256 of TLS certificate")
	}
	if err := parsed.VerifySignature(signPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func generateTestRelayKeys(t *testing.T) *RelayKeys {
	t.Helper()
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatalf("GenerateRelayKeys: %v", err)
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

	// VERSIONS 2 字节帧之后：CERTS / AUTH_CHALLENGE / NETINFO 必须是 4 字节 CircID
	r := bytes.NewReader(written)
	versionsOut, err := cell.DecodeCellLink(r, 2)
	if err != nil {
		t.Fatalf("decode server VERSIONS: %v", err)
	}
	if versionsOut.Command != cell.CmdVersions {
		t.Fatalf("first written cell = %s, want VERSIONS", versionsOut.Command)
	}
	certsOut, err := cell.DecodeCellLink(r, 4)
	if err != nil {
		t.Fatalf("decode server CERTS with 4-byte CircID: %v", err)
	}
	if certsOut.Command != cell.CmdCerts {
		t.Fatalf("second written cell = %s, want CERTS", certsOut.Command)
	}
	authOut, err := cell.DecodeCellLink(r, 4)
	if err != nil {
		t.Fatalf("decode server AUTH_CHALLENGE with 4-byte CircID: %v", err)
	}
	if authOut.Command != cell.CmdAuthChallenge {
		t.Fatalf("third written cell = %s, want AUTH_CHALLENGE", authOut.Command)
	}
	netinfoOut, err := cell.DecodeCellLink(r, 4)
	if err != nil {
		t.Fatalf("decode server NETINFO with 4-byte CircID: %v", err)
	}
	if netinfoOut.Command != cell.CmdNetinfo {
		t.Fatalf("fourth written cell = %s, want NETINFO", netinfoOut.Command)
	}
	if r.Len() != 0 {
		t.Fatalf("unexpected trailing handshake bytes: %d", r.Len())
	}

	parsed, err := protocol.ParseCERTSCell(certsOut)
	if err != nil {
		t.Fatalf("ParseCERTSCell: %v", err)
	}
	if err := parsed.ValidateSignatures(); err != nil {
		t.Fatalf("handshake CERTS ValidateSignatures: %v", err)
	}
	if err := assertAuthChallengePayload(authOut.Payload); err != nil {
		t.Fatal(err)
	}
}

func TestSendAuthChallenge(t *testing.T) {
	handler := NewLinkProtocolHandler(generateTestRelayKeys(t), nil)
	handler.setCircIDLen(4)
	conn := newMockConn()
	if err := handler.sendAuthChallenge(conn); err != nil {
		t.Fatal(err)
	}
	cells, err := conn.getWrittenCells(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].Command != cell.CmdAuthChallenge {
		t.Fatalf("got %+v", cells)
	}
	if err := assertAuthChallengePayload(cells[0].Payload); err != nil {
		t.Fatal(err)
	}
}

func assertAuthChallengePayload(p []byte) error {
	if len(p) < 36 {
		return fmt.Errorf("AUTH_CHALLENGE too short: %d", len(p))
	}
	n := int(binary.BigEndian.Uint16(p[32:34]))
	if n < 1 {
		return fmt.Errorf("N_Methods = %d", n)
	}
	if len(p) < 34+2*n {
		return fmt.Errorf("AUTH_CHALLENGE truncated methods")
	}
	var has3 bool
	for i := 0; i < n; i++ {
		m := binary.BigEndian.Uint16(p[34+2*i : 36+2*i])
		if m == authMethodEd25519SHA256RFC5705 {
			has3 = true
		}
	}
	if !has3 {
		return fmt.Errorf("AUTH_CHALLENGE missing method 3")
	}
	return nil
}

func TestReceiveNetinfoSkipsInitiatorHandshakeCells(t *testing.T) {
	handler := NewLinkProtocolHandler(generateTestRelayKeys(t), nil)
	handler.setCircIDLen(4)

	var buf bytes.Buffer
	certs := cell.NewCell(0, cell.CmdCerts)
	certs.Payload = []byte{0}
	if err := certs.EncodeLink(&buf, 4); err != nil {
		t.Fatal(err)
	}
	pad := cell.NewCell(0, cell.CmdVPadding)
	pad.Payload = []byte{1, 2, 3}
	if err := pad.EncodeLink(&buf, 4); err != nil {
		t.Fatal(err)
	}
	netinfo := cell.NewCell(0, cell.CmdNetinfo)
	netinfo.Payload = []byte{0, 0, 0, 1, 0x04, 4, 127, 0, 0, 1, 0}
	if err := netinfo.EncodeLink(&buf, 4); err != nil {
		t.Fatal(err)
	}

	conn := newMockConn()
	conn.addReadData(buf.Bytes())
	if err := handler.receiveInitiatorFinish(context.Background(), conn, nil); err != nil {
		t.Fatalf("receiveInitiatorFinish: %v", err)
	}
}

func TestReceiveInitiatorFinishRejectsBadAuthenticate(t *testing.T) {
	handler := NewLinkProtocolHandler(generateTestRelayKeys(t), nil)
	handler.setCircIDLen(4)
	handler.slog = bytes.Repeat([]byte{0x11}, 32)

	var buf bytes.Buffer
	certs := cell.NewCell(0, cell.CmdCerts)
	certs.Payload = []byte{0}
	if err := certs.EncodeLink(&buf, 4); err != nil {
		t.Fatal(err)
	}
	auth := cell.NewCell(0, cell.CmdAuthenticate)
	auth.Payload = []byte{0, 3, 0, 4, 0, 0, 0, 0}
	if err := auth.EncodeLink(&buf, 4); err != nil {
		t.Fatal(err)
	}
	netinfo := cell.NewCell(0, cell.CmdNetinfo)
	netinfo.Payload = []byte{0, 0, 0, 1, 0x04, 4, 127, 0, 0, 1, 0}
	if err := netinfo.EncodeLink(&buf, 4); err != nil {
		t.Fatal(err)
	}
	conn := newMockConn()
	conn.addReadData(buf.Bytes())
	if err := handler.receiveInitiatorFinish(context.Background(), conn, nil); err == nil {
		t.Fatal("bogus AUTHENTICATE must fail")
	}
}

func TestHandleConnectionAuthorityInitiatorCells(t *testing.T) {
	handler := NewLinkProtocolHandler(generateTestRelayKeys(t), nil)

	var inbound bytes.Buffer
	inbound.Write(inboundVersionsWire2())
	certs := cell.NewCell(0, cell.CmdCerts)
	certs.Payload = []byte{0}
	if err := certs.EncodeLink(&inbound, 4); err != nil {
		t.Fatal(err)
	}
	netinfo := cell.NewCell(0, cell.CmdNetinfo)
	netinfo.Payload = []byte{0, 0, 0, 1, 0x04, 4, 10, 0, 0, 1, 0}
	if err := netinfo.EncodeLink(&inbound, 4); err != nil {
		t.Fatal(err)
	}

	conn := newMockConn()
	conn.addReadData(inbound.Bytes())
	orConn, err := handler.HandleConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("HandleConnection: %v", err)
	}
	if orConn.negotiatedVersion != 5 || orConn.circIDLen != 4 {
		t.Fatalf("version=%d circIDLen=%d", orConn.negotiatedVersion, orConn.circIDLen)
	}
}

func TestInboundHandshakeNetPipeClientNetinfo(t *testing.T) {
	runInboundHandshakePipe(t, false)
}

func TestInboundHandshakeNetPipeRelayInitiator(t *testing.T) {
	runInboundHandshakePipe(t, true)
}

func runInboundHandshakePipe(t *testing.T, initiatorIsRelay bool) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	handler := NewLinkProtocolHandler(generateTestRelayKeys(t), nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := handler.HandleConnection(context.Background(), serverConn)
		errCh <- err
	}()

	if _, err := clientConn.Write(inboundVersionsWire2()); err != nil {
		t.Fatal(err)
	}
	versions, err := cell.DecodeCellLink(clientConn, 2)
	if err != nil {
		t.Fatalf("read VERSIONS: %v", err)
	}
	if versions.Command != cell.CmdVersions {
		t.Fatalf("first cell = %s", versions.Command)
	}
	certs, err := cell.DecodeCellLink(clientConn, 4)
	if err != nil {
		t.Fatalf("read CERTS: %v", err)
	}
	if certs.Command != cell.CmdCerts {
		t.Fatalf("second cell = %s", certs.Command)
	}
	parsed, err := protocol.ParseCERTSCell(certs)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.ValidateSignatures(); err != nil {
		t.Fatalf("CERTS chain: %v", err)
	}
	auth, err := cell.DecodeCellLink(clientConn, 4)
	if err != nil {
		t.Fatalf("read AUTH_CHALLENGE: %v", err)
	}
	if auth.Command != cell.CmdAuthChallenge {
		t.Fatalf("third cell = %s", auth.Command)
	}
	if err := assertAuthChallengePayload(auth.Payload); err != nil {
		t.Fatal(err)
	}
	netinfoIn, err := cell.DecodeCellLink(clientConn, 4)
	if err != nil {
		t.Fatalf("read NETINFO: %v", err)
	}
	if netinfoIn.Command != cell.CmdNetinfo {
		t.Fatalf("fourth cell = %s", netinfoIn.Command)
	}

	if initiatorIsRelay {
		dummy := cell.NewCell(0, cell.CmdCerts)
		dummy.Payload = []byte{0}
		if err := dummy.EncodeLink(clientConn, 4); err != nil {
			t.Fatal(err)
		}
		authen := cell.NewCell(0, cell.CmdAuthenticate)
		authen.Payload = []byte{0, 3, 0, 0}
		if err := authen.EncodeLink(clientConn, 4); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("bogus AUTHENTICATE must fail handshake")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("server handshake timeout")
		}
		return
	}
	netinfoOut := cell.NewCell(0, cell.CmdNetinfo)
	netinfoOut.Payload = []byte{0, 0, 0, 1, 0x04, 4, 127, 0, 0, 1, 0}
	if err := netinfoOut.EncodeLink(clientConn, 4); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake timeout")
	}
}

func TestSendCertsRejectsIncompleteKeys(t *testing.T) {
	handler := NewLinkProtocolHandler(&RelayKeys{}, nil)
	if err := handler.sendCerts(newMockConn()); err == nil {
		t.Fatal("expected error for empty keys")
	}

	keys := generateTestRelayKeys(t)
	keys.TLSCert = []byte("not-a-certificate")
	handler = NewLinkProtocolHandler(keys, nil)
	if err := handler.sendCerts(newMockConn()); err == nil {
		t.Fatal("expected error for invalid TLS certificate")
	}
}
