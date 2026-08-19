package circuit

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// TestParseResolvedCell tests parsing of RELAY_RESOLVED cells
func TestParseResolvedCell(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantType  byte
		wantAddrs []string
		wantHost  string
		wantTTL   uint32
		wantError byte
		expectErr bool
	}{
		{
			name: "IPv4 response",
			data: func() []byte {
				// TYPE (0x04) | LENGTH (4) | IPv4 (192.0.2.1) | TTL (3600)
				data := make([]byte, 10)
				data[0] = DNSTypeIPv4
				data[1] = 4
				copy(data[2:6], []byte{192, 0, 2, 1})
				binary.BigEndian.PutUint32(data[6:10], 3600)
				return data
			}(),
			wantType:  DNSTypeIPv4,
			wantAddrs: []string{"192.0.2.1"},
			wantTTL:   3600,
			expectErr: false,
		},
		{
			name: "IPv6 response",
			data: func() []byte {
				// TYPE (0x06) | LENGTH (16) | IPv6 (2001:db8::1) | TTL (7200)
				data := make([]byte, 22)
				data[0] = DNSTypeIPv6
				data[1] = 16
				ip := net.ParseIP("2001:db8::1").To16()
				copy(data[2:18], ip)
				binary.BigEndian.PutUint32(data[18:22], 7200)
				return data
			}(),
			wantType:  DNSTypeIPv6,
			wantAddrs: []string{"2001:db8::1"},
			wantTTL:   7200,
			expectErr: false,
		},
		{
			name: "Hostname response (PTR)",
			data: func() []byte {
				// TYPE (0x00) | LENGTH (15) | "www.example.com\x00" | TTL (1800)
				hostname := "www.example.com\x00"
				data := make([]byte, 2+len(hostname)+4)
				data[0] = DNSTypeHostname
				data[1] = byte(len(hostname))
				copy(data[2:2+len(hostname)], []byte(hostname))
				binary.BigEndian.PutUint32(data[2+len(hostname):], 1800)
				return data
			}(),
			wantType:  DNSTypeHostname,
			wantHost:  "www.example.com",
			wantTTL:   1800,
			expectErr: false,
		},
		{
			name: "Error response - transient string (C Tor)",
			data: func() []byte {
				msg := "Error resolving hostname"
				data := make([]byte, 2+len(msg)+4)
				data[0] = DNSTypeError
				data[1] = byte(len(msg))
				copy(data[2:], msg)
				binary.BigEndian.PutUint32(data[2+len(msg):], 0)
				return data
			}(),
			wantType:  DNSTypeError,
			wantError: DNSTypeError,
			wantTTL:   0,
			expectErr: false,
		},
		{
			name: "Error response - nontransient string",
			data: func() []byte {
				msg := "Error resolving hostname"
				data := make([]byte, 2+len(msg)+4)
				data[0] = DNSTypeErrorTTL
				data[1] = byte(len(msg))
				copy(data[2:], msg)
				binary.BigEndian.PutUint32(data[2+len(msg):], 60)
				return data
			}(),
			wantType:  DNSTypeErrorTTL,
			wantError: DNSTypeErrorTTL,
			wantTTL:   60,
			expectErr: false,
		},
		{
			name: "Multiple IPv4 then IPv6 — keep all, prefer IPv4 type",
			data: func() []byte {
				data := make([]byte, 10+10+22)
				data[0] = DNSTypeIPv4
				data[1] = 4
				copy(data[2:6], []byte{192, 0, 2, 1})
				binary.BigEndian.PutUint32(data[6:10], 3600)
				data[10] = DNSTypeIPv4
				data[11] = 4
				copy(data[12:16], []byte{192, 0, 2, 2})
				binary.BigEndian.PutUint32(data[16:20], 1800)
				data[20] = DNSTypeIPv6
				data[21] = 16
				copy(data[22:38], net.ParseIP("2001:db8::1").To16())
				binary.BigEndian.PutUint32(data[38:42], 7200)
				return data
			}(),
			wantType:  DNSTypeIPv4,
			wantAddrs: []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"},
			wantTTL:   3600,
			expectErr: false,
		},
		{
			name:      "Empty data",
			data:      []byte{},
			expectErr: true,
		},
		{
			name: "Invalid IPv4 length",
			data: func() []byte {
				// TYPE (0x04) | LENGTH (3) - wrong! | garbage | TTL
				data := make([]byte, 9)
				data[0] = DNSTypeIPv4
				data[1] = 3 // Should be 4
				return data
			}(),
			expectErr: true,
		},
		{
			name: "Invalid IPv6 length",
			data: func() []byte {
				// TYPE (0x06) | LENGTH (8) - wrong! | garbage | TTL
				data := make([]byte, 14)
				data[0] = DNSTypeIPv6
				data[1] = 8 // Should be 16
				return data
			}(),
			expectErr: true,
		},
		{
			name:      "Truncated data",
			data:      []byte{0x04, 0x04, 0x01}, // Too short
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseResolvedCell(tt.data)

			if tt.expectErr {
				if err == nil {
					t.Errorf("parseResolvedCell() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("parseResolvedCell() unexpected error: %v", err)
				return
			}

			if result.Type != tt.wantType {
				t.Errorf("parseResolvedCell() Type = %d, want %d", result.Type, tt.wantType)
			}

			if result.TTL != tt.wantTTL {
				t.Errorf("parseResolvedCell() TTL = %d, want %d", result.TTL, tt.wantTTL)
			}

			if tt.wantType == DNSTypeError || tt.wantType == DNSTypeErrorTTL {
				if result.Error != tt.wantError {
					t.Errorf("parseResolvedCell() Error = %d, want %d", result.Error, tt.wantError)
				}
				if result.ErrorMessage == "" {
					t.Errorf("parseResolvedCell() missing ErrorMessage for 0xF0/0xF1")
				}
			}

			if tt.wantHost != "" {
				if result.Hostname != tt.wantHost {
					t.Errorf("parseResolvedCell() Hostname = %q, want %q", result.Hostname, tt.wantHost)
				}
			}

			if len(tt.wantAddrs) > 0 {
				if len(result.Addresses) != len(tt.wantAddrs) {
					t.Errorf("parseResolvedCell() got %d addresses, want %d", len(result.Addresses), len(tt.wantAddrs))
				} else {
					for i, wantAddr := range tt.wantAddrs {
						if result.Addresses[i].String() != wantAddr {
							t.Errorf("parseResolvedCell() Addresses[%d] = %v, want %v", i, result.Addresses[i], wantAddr)
						}
					}
				}
			}
		})
	}
}

// TestDNSConstants verifies DNS constant values match the spec
func TestDNSConstants(t *testing.T) {
	// Verify DNS types
	if DNSTypeHostname != 0x00 {
		t.Errorf("DNSTypeHostname = 0x%02X, want 0x00", DNSTypeHostname)
	}
	if DNSTypeIPv4 != 0x04 {
		t.Errorf("DNSTypeIPv4 = 0x%02X, want 0x04", DNSTypeIPv4)
	}
	if DNSTypeIPv6 != 0x06 {
		t.Errorf("DNSTypeIPv6 = 0x%02X, want 0x06", DNSTypeIPv6)
	}
	if DNSTypeError != 0xF0 {
		t.Errorf("DNSTypeError = 0x%02X, want 0xF0", DNSTypeError)
	}

	// Verify error codes
	if DNSErrorNotExist != 0x03 {
		t.Errorf("DNSErrorNotExist = 0x%02X, want 0x03", DNSErrorNotExist)
	}
	if DNSErrorServerFailure != 0x02 {
		t.Errorf("DNSErrorServerFailure = 0x%02X, want 0x02", DNSErrorServerFailure)
	}
}

// TestResolveHostnamePayload tests the RELAY_RESOLVE payload format for hostname queries
func TestResolveHostnamePayload(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantLen  int
	}{
		{
			name:     "Simple hostname",
			hostname: "example.com",
			wantLen:  12, // "example.com\x00" = 12 bytes
		},
		{
			name:     "Subdomain",
			hostname: "www.example.com",
			wantLen:  16, // "www.example.com\x00" = 16 bytes
		},
		{
			name:     "Long hostname",
			hostname: "very.long.subdomain.example.com",
			wantLen:  32, // "very.long.subdomain.example.com\x00" = 32 bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create payload as would be done in ResolveHostname
			payload := append([]byte(tt.hostname), 0x00)

			if len(payload) != tt.wantLen {
				t.Errorf("Payload length = %d, want %d", len(payload), tt.wantLen)
			}

			// Verify null termination
			if payload[len(payload)-1] != 0x00 {
				t.Errorf("Payload not null-terminated")
			}

			// Verify content
			if string(payload[:len(payload)-1]) != tt.hostname {
				t.Errorf("Payload content = %q, want %q", string(payload[:len(payload)-1]), tt.hostname)
			}
		})
	}
}

// TestResolveIPPayload 验收 PTR 载荷是 NUL 结尾的 arpa 名，不是二进制 TYPE|LENGTH|ADDRESS。
func TestResolveIPPayload(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "IPv4", ip: "192.0.2.1", want: "1.2.0.192.in-addr.arpa"},
		{name: "IPv6", ip: "2001:db8::1", want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipAddr := net.ParseIP(tt.ip)
			if ipAddr == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			name, err := PTRHostname(ipAddr)
			if err != nil {
				t.Fatalf("PTRHostname: %v", err)
			}
			if name != tt.want {
				t.Errorf("PTRHostname() = %q, want %q", name, tt.want)
			}
			payload := buildResolvePayload(name)
			if payload[len(payload)-1] != 0x00 {
				t.Error("PTR payload not NUL-terminated")
			}
			if string(payload[:len(payload)-1]) != tt.want {
				t.Errorf("payload name = %q, want %q", payload[:len(payload)-1], tt.want)
			}
		})
	}
}

// TestDNSResultValidation tests DNSResult structure validation
func TestDNSResultValidation(t *testing.T) {
	tests := []struct {
		name   string
		result *DNSResult
		valid  bool
	}{
		{
			name: "Valid IPv4 result",
			result: &DNSResult{
				Type:      DNSTypeIPv4,
				TTL:       3600,
				Addresses: []net.IP{net.ParseIP("192.0.2.1")},
			},
			valid: true,
		},
		{
			name: "Valid IPv6 result",
			result: &DNSResult{
				Type:      DNSTypeIPv6,
				TTL:       7200,
				Addresses: []net.IP{net.ParseIP("2001:db8::1")},
			},
			valid: true,
		},
		{
			name: "Valid hostname result",
			result: &DNSResult{
				Type:     DNSTypeHostname,
				TTL:      1800,
				Hostname: "example.com",
			},
			valid: true,
		},
		{
			name: "Valid error result",
			result: &DNSResult{
				Type:  DNSTypeError,
				TTL:   0,
				Error: DNSErrorNotExist,
			},
			valid: true,
		},
		{
			name: "Multiple IPv4 addresses",
			result: &DNSResult{
				Type: DNSTypeIPv4,
				TTL:  3600,
				Addresses: []net.IP{
					net.ParseIP("192.0.2.1"),
					net.ParseIP("192.0.2.2"),
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation
			if tt.result.Type == DNSTypeIPv4 || tt.result.Type == DNSTypeIPv6 {
				if len(tt.result.Addresses) == 0 {
					t.Errorf("IP result should have addresses")
				}
			}

			if tt.result.Type == DNSTypeHostname {
				if tt.result.Hostname == "" {
					t.Errorf("Hostname result should have hostname")
				}
			}

			if tt.result.Type == DNSTypeError {
				// Error results should have error code
				_ = tt.result.Error
			}
		})
	}
}

// mockConnection 记录发出的 RELAY cell StreamID，供 mock 应答配对。
type mockConnection struct {
	lastStreamID uint16
}

func (m *mockConnection) SendCell(c *cell.Cell) error {
	if len(c.Payload) >= 5 {
		m.lastStreamID = binary.BigEndian.Uint16(c.Payload[3:5])
	}
	return nil
}

// MockCircuitForDNS 注入与发出 RESOLVE 相同 StreamID 的 RELAY_RESOLVED。
func MockCircuitForDNS(t *testing.T, responseData []byte) *Circuit {
	t.Helper()
	conn := &mockConnection{}
	c := &Circuit{
		ID:               1,
		State:            StateOpen,
		relayReceiveChan: make(chan *cell.RelayCell, 1),
		conn:             conn,
		nextStreamID:     1,
		usedStreamIDs:    make(map[uint16]struct{}),
	}

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if conn.lastStreamID != 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		sid := conn.lastStreamID
		if sid == 0 {
			t.Errorf("RESOLVE 未发出非 0 StreamID")
			return
		}
		resolvedCell, err := cell.NewRelayCell(sid, cell.RelayResolved, responseData)
		if err != nil {
			t.Errorf("Failed to create relay cell: %v", err)
			return
		}
		c.relayReceiveChan <- resolvedCell
	}()

	return c
}

// TestResolveHostnameIntegration tests the full ResolveHostname flow
func TestResolveHostnameIntegration(t *testing.T) {
	// Create response data for "example.com" -> "192.0.2.1"
	responseData := make([]byte, 10)
	responseData[0] = DNSTypeIPv4
	responseData[1] = 4
	copy(responseData[2:6], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint32(responseData[6:10], 3600)

	c := MockCircuitForDNS(t, responseData)

	ctx := context.Background()
	result, err := c.ResolveHostname(ctx, "example.com")
	if err != nil {
		t.Fatalf("ResolveHostname() error = %v", err)
	}

	if result.Type != DNSTypeIPv4 {
		t.Errorf("Result type = %d, want %d", result.Type, DNSTypeIPv4)
	}

	if len(result.Addresses) != 1 {
		t.Errorf("Result has %d addresses, want 1", len(result.Addresses))
	}

	if result.Addresses[0].String() != "192.0.2.1" {
		t.Errorf("Result address = %v, want 192.0.2.1", result.Addresses[0])
	}

	if result.TTL != 3600 {
		t.Errorf("Result TTL = %d, want 3600", result.TTL)
	}
}

// TestResolveIPIntegration tests the full ResolveIP flow
func TestResolveIPIntegration(t *testing.T) {
	// Create response data for PTR query: "192.0.2.1" -> "example.com"
	hostname := "example.com\x00"
	responseData := make([]byte, 2+len(hostname)+4)
	responseData[0] = DNSTypeHostname
	responseData[1] = byte(len(hostname))
	copy(responseData[2:2+len(hostname)], []byte(hostname))
	binary.BigEndian.PutUint32(responseData[2+len(hostname):], 1800)

	c := MockCircuitForDNS(t, responseData)

	ctx := context.Background()
	result, err := c.ResolveIP(ctx, net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("ResolveIP() error = %v", err)
	}

	if result.Type != DNSTypeHostname {
		t.Errorf("Result type = %d, want %d", result.Type, DNSTypeHostname)
	}

	if result.Hostname != "example.com" {
		t.Errorf("Result hostname = %q, want %q", result.Hostname, "example.com")
	}

	if result.TTL != 1800 {
		t.Errorf("Result TTL = %d, want 1800", result.TTL)
	}
}

// TestResolveHostnameErrors tests error handling in ResolveHostname
func TestResolveHostnameErrors(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		expectError string
	}{
		{
			name:        "Empty hostname",
			hostname:    "",
			expectError: "hostname cannot be empty",
		},
		{
			name:        "NUL in hostname",
			hostname:    "exam\x00ple.com",
			expectError: "hostname contains NUL",
		},
		{
			name:        "onion must not go to exit DNS",
			hostname:    "thehiddenwiki7fhdx5oawttis2ggfurncbhcivilization6vhogt4n4kkqid.onion",
			expectError: "onion addresses must not be resolved via RELAY_RESOLVE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Circuit{
				ID:               1,
				State:            StateOpen,
				relayReceiveChan: make(chan *cell.RelayCell, 1),
			}

			ctx := context.Background()
			_, err := c.ResolveHostname(ctx, tt.hostname)
			if err == nil {
				t.Errorf("ResolveHostname() expected error but got none")
			} else if err.Error() != tt.expectError {
				t.Errorf("ResolveHostname() error = %q, want %q", err.Error(), tt.expectError)
			}
		})
	}
}

// TestResolveIPErrors tests error handling in ResolveIP
func TestResolveIPErrors(t *testing.T) {
	tests := []struct {
		name        string
		ip          net.IP
		expectError string
	}{
		{
			name:        "Nil IP address",
			ip:          nil,
			expectError: "IP address cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Circuit{
				ID:               1,
				State:            StateOpen,
				relayReceiveChan: make(chan *cell.RelayCell, 1),
			}

			ctx := context.Background()
			_, err := c.ResolveIP(ctx, tt.ip)
			if err == nil {
				t.Errorf("ResolveIP() expected error but got none")
			} else if err.Error() != tt.expectError {
				t.Errorf("ResolveIP() error = %q, want %q", err.Error(), tt.expectError)
			}
		})
	}
}

func TestAllocateStreamIDNeverZero(t *testing.T) {
	c := NewCircuit(1)
	seen := make(map[uint16]bool)
	for i := 0; i < 64; i++ {
		id, err := c.AllocateStreamID()
		if err != nil {
			t.Fatalf("AllocateStreamID: %v", err)
		}
		if id == 0 {
			t.Fatal("AllocateStreamID returned 0")
		}
		if seen[id] {
			t.Fatalf("duplicate stream ID %d", id)
		}
		seen[id] = true
	}
	c.ReleaseStreamID(1)
	c.nextStreamID = 1
	id, err := c.AllocateStreamID()
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatalf("released ID 1 not reused, got %d", id)
	}
}
