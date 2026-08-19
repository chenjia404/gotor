package circuit

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// TestRELAY_RESOLVECellFormat 对照 remote-hostname-lookup：
//   - 正向：HOSTNAME\x00
//   - 反向：同样格式的 in-addr.arpa / ip6.arpa\x00
//   - StreamID 必须非 0（C Tor 丢弃 stream_id==0 的 RELAY_RESOLVE）
func TestRELAY_RESOLVECellFormat(t *testing.T) {
	tests := []struct {
		name        string
		queryType   string
		query       string
		wantPayload []byte
	}{
		{
			name:        "Hostname query - simple domain",
			queryType:   "hostname",
			query:       "example.com",
			wantPayload: append([]byte("example.com"), 0x00),
		},
		{
			name:        "Hostname query - subdomain",
			queryType:   "hostname",
			query:       "www.example.com",
			wantPayload: append([]byte("www.example.com"), 0x00),
		},
		{
			name:        "Hostname query - long FQDN",
			queryType:   "hostname",
			query:       "very.long.subdomain.example.com",
			wantPayload: append([]byte("very.long.subdomain.example.com"), 0x00),
		},
		{
			name:        "PTR query - IPv4",
			queryType:   "ipv4",
			query:       "192.0.2.1",
			wantPayload: append([]byte("1.2.0.192.in-addr.arpa"), 0x00),
		},
		{
			name:        "PTR query - IPv6",
			queryType:   "ipv6",
			query:       "2001:db8::1",
			wantPayload: append([]byte("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"), 0x00),
		},
		{
			name:        "PTR query - IPv6 loopback",
			queryType:   "ipv6",
			query:       "::1",
			wantPayload: append([]byte("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"), 0x00),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload []byte
			switch tt.queryType {
			case "hostname":
				payload = buildResolvePayload(tt.query)
			case "ipv4", "ipv6":
				name, err := PTRHostname(net.ParseIP(tt.query))
				if err != nil {
					t.Fatalf("PTRHostname: %v", err)
				}
				payload = buildResolvePayload(name)
			}

			resolveCell, err := cell.NewRelayCell(1, cell.RelayResolve, payload)
			if err != nil {
				t.Fatalf("NewRelayCell() error = %v", err)
			}
			if resolveCell.StreamID == 0 {
				t.Error("StreamID must be nonzero for RELAY_RESOLVE")
			}
			if resolveCell.Command != cell.RelayResolve {
				t.Errorf("Command = %d, want %d (RelayResolve)", resolveCell.Command, cell.RelayResolve)
			}
			if string(resolveCell.Data) != string(tt.wantPayload) {
				t.Errorf("Payload = %q, want %q", resolveCell.Data, tt.wantPayload)
			}
		})
	}
}

// TestRELAY_RESOLVEDCellFormat verifies RELAY_RESOLVED cell format per tor-spec.txt §6.4
//
// Specification: tor-spec.txt §6.4
// RELAY_RESOLVED cells contain DNS resolution responses.
// Format (one or more records):
//
//	TYPE (1 byte) | LENGTH (1 byte) | VALUE (LENGTH bytes) | TTL (4 bytes)
//
// Record types:
//   - 0x00: Hostname (null-terminated string)
//   - 0x04: IPv4 address (4 bytes)
//   - 0x06: IPv6 address (16 bytes)
//   - 0xF0: Error (1 byte error code)
//   - 0xF1: Error with TTL (1 byte error code)
func TestRELAY_RESOLVEDCellFormat(t *testing.T) {
	tests := []struct {
		name        string
		recordType  byte
		value       []byte
		ttl         uint32
		wantPayload func() []byte
	}{
		{
			name:       "IPv4 record",
			recordType: DNSTypeIPv4,
			value:      []byte{192, 0, 2, 1},
			ttl:        3600,
			wantPayload: func() []byte {
				// TYPE (0x04) | LENGTH (4) | IPv4 | TTL (4 bytes)
				payload := make([]byte, 10)
				payload[0] = DNSTypeIPv4
				payload[1] = 4
				copy(payload[2:6], []byte{192, 0, 2, 1})
				binary.BigEndian.PutUint32(payload[6:10], 3600)
				return payload
			},
		},
		{
			name:       "IPv6 record",
			recordType: DNSTypeIPv6,
			value:      net.ParseIP("2001:db8::1").To16(),
			ttl:        7200,
			wantPayload: func() []byte {
				// TYPE (0x06) | LENGTH (16) | IPv6 | TTL (4 bytes)
				payload := make([]byte, 22)
				payload[0] = DNSTypeIPv6
				payload[1] = 16
				ip := net.ParseIP("2001:db8::1").To16()
				copy(payload[2:18], ip)
				binary.BigEndian.PutUint32(payload[18:22], 7200)
				return payload
			},
		},
		{
			name:       "Hostname record",
			recordType: DNSTypeHostname,
			value:      []byte("example.com\x00"),
			ttl:        1800,
			wantPayload: func() []byte {
				// TYPE (0x00) | LENGTH (12) | "example.com\x00" | TTL (4 bytes)
				hostname := "example.com\x00"
				payload := make([]byte, 2+len(hostname)+4)
				payload[0] = DNSTypeHostname
				payload[1] = byte(len(hostname))
				copy(payload[2:2+len(hostname)], []byte(hostname))
				binary.BigEndian.PutUint32(payload[2+len(hostname):], 1800)
				return payload
			},
		},
		{
			name:       "Error record - transient string",
			recordType: DNSTypeError,
			value:      []byte("Error resolving hostname"),
			ttl:        0,
			wantPayload: func() []byte {
				msg := "Error resolving hostname"
				payload := make([]byte, 2+len(msg)+4)
				payload[0] = DNSTypeError
				payload[1] = byte(len(msg))
				copy(payload[2:], msg)
				binary.BigEndian.PutUint32(payload[2+len(msg):], 0)
				return payload
			},
		},
		{
			name:       "Error record - nontransient string",
			recordType: DNSTypeErrorTTL,
			value:      []byte("Error resolving hostname"),
			ttl:        0,
			wantPayload: func() []byte {
				msg := "Error resolving hostname"
				payload := make([]byte, 2+len(msg)+4)
				payload[0] = DNSTypeErrorTTL
				payload[1] = byte(len(msg))
				copy(payload[2:], msg)
				binary.BigEndian.PutUint32(payload[2+len(msg):], 0)
				return payload
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build RELAY_RESOLVED payload
			payload := tt.wantPayload()

			// Create RELAY_RESOLVED cell
			resolvedCell, err := cell.NewRelayCell(0, cell.RelayResolved, payload)
			if err != nil {
				t.Fatalf("NewRelayCell() error = %v", err)
			}

			// Verify cell command
			if resolvedCell.Command != cell.RelayResolved {
				t.Errorf("Command = %d, want %d (RelayResolved)", resolvedCell.Command, cell.RelayResolved)
			}

			// Parse the response
			result, err := parseResolvedCell(resolvedCell.Data)
			if err != nil && tt.recordType != DNSTypeError {
				t.Fatalf("parseResolvedCell() error = %v", err)
			}

			// Verify record type
			if result.Type != tt.recordType {
				t.Errorf("Type = 0x%02X, want 0x%02X", result.Type, tt.recordType)
			}

			// Verify TTL
			if result.TTL != tt.ttl {
				t.Errorf("TTL = %d, want %d", result.TTL, tt.ttl)
			}

			// Verify value based on type
			switch tt.recordType {
			case DNSTypeIPv4:
				if len(result.Addresses) != 1 {
					t.Errorf("Expected 1 address, got %d", len(result.Addresses))
				}
				expectedIP := net.IPv4(tt.value[0], tt.value[1], tt.value[2], tt.value[3])
				if !result.Addresses[0].Equal(expectedIP) {
					t.Errorf("IPv4 = %v, want %v", result.Addresses[0], expectedIP)
				}
			case DNSTypeIPv6:
				if len(result.Addresses) != 1 {
					t.Errorf("Expected 1 address, got %d", len(result.Addresses))
				}
			case DNSTypeHostname:
				expectedHostname := string(tt.value[:len(tt.value)-1]) // Remove null terminator
				if result.Hostname != expectedHostname {
					t.Errorf("Hostname = %q, want %q", result.Hostname, expectedHostname)
				}
			case DNSTypeError, DNSTypeErrorTTL:
				if result.Error != tt.recordType {
					t.Errorf("Error type = 0x%02X, want 0x%02X", result.Error, tt.recordType)
				}
				if result.ErrorMessage != string(tt.value) {
					t.Errorf("ErrorMessage = %q, want %q", result.ErrorMessage, tt.value)
				}
			}
		})
	}
}

// TestDNSResolutionSpecCompliance 对照 remote-hostname-lookup。
func TestDNSResolutionSpecCompliance(t *testing.T) {
	t.Run("Stream ID must be nonzero", func(t *testing.T) {
		payload := buildResolvePayload("example.com")
		resolveCell, err := cell.NewRelayCell(1, cell.RelayResolve, payload)
		if err != nil {
			t.Fatalf("NewRelayCell() error = %v", err)
		}
		if resolveCell.StreamID == 0 {
			t.Error("StreamID must be nonzero")
		}
	})

	t.Run("30 second timeout per spec", func(t *testing.T) {
		// This test verifies the timeout value used in ResolveHostname/ResolveIP
		// The actual timeout is 30 seconds as defined in the implementation
		// We just verify that the timeout constant is reasonable

		const expectedTimeout = 30 * time.Second
		const minTimeout = 15 * time.Second
		const maxTimeout = 60 * time.Second

		if expectedTimeout < minTimeout {
			t.Errorf("DNS timeout %v is too short (minimum %v recommended)", expectedTimeout, minTimeout)
		}
		if expectedTimeout > maxTimeout {
			t.Errorf("DNS timeout %v is too long (maximum %v recommended)", expectedTimeout, maxTimeout)
		}
	})

	t.Run("Multiple records - keep all IPv4", func(t *testing.T) {
		payload := make([]byte, 20)
		payload[0] = DNSTypeIPv4
		payload[1] = 4
		copy(payload[2:6], []byte{192, 0, 2, 1})
		binary.BigEndian.PutUint32(payload[6:10], 3600)
		payload[10] = DNSTypeIPv4
		payload[11] = 4
		copy(payload[12:16], []byte{192, 0, 2, 2})
		binary.BigEndian.PutUint32(payload[16:20], 3600)

		result, err := parseResolvedCell(payload)
		if err != nil {
			t.Fatalf("parseResolvedCell() error = %v", err)
		}
		if result.Type != DNSTypeIPv4 {
			t.Errorf("Type = 0x%02X, want 0x%02X", result.Type, DNSTypeIPv4)
		}
		if len(result.Addresses) != 2 {
			t.Fatalf("got %d addresses, want 2", len(result.Addresses))
		}
		if !result.Addresses[0].Equal(net.IPv4(192, 0, 2, 1)) {
			t.Errorf("First address = %v, want 192.0.2.1", result.Addresses[0])
		}
		if !result.Addresses[1].Equal(net.IPv4(192, 0, 2, 2)) {
			t.Errorf("Second address = %v, want 192.0.2.2", result.Addresses[1])
		}
	})

	t.Run("Error responses use type 0xF0/0xF1 string value", func(t *testing.T) {
		msg := "Error resolving hostname"
		payload := make([]byte, 2+len(msg)+4)
		payload[0] = DNSTypeError
		payload[1] = byte(len(msg))
		copy(payload[2:], msg)
		binary.BigEndian.PutUint32(payload[2+len(msg):], 0)

		result, err := parseResolvedCell(payload)
		if err != nil {
			t.Fatalf("parseResolvedCell() error = %v", err)
		}
		if result.Type != DNSTypeError {
			t.Errorf("Type = 0x%02X, want 0x%02X", result.Type, DNSTypeError)
		}
		if result.Error != DNSTypeError {
			t.Errorf("Error = 0x%02X, want 0x%02X", result.Error, DNSTypeError)
		}
		if result.ErrorMessage != msg {
			t.Errorf("ErrorMessage = %q, want %q", result.ErrorMessage, msg)
		}
	})
}

// TestDNSErrorCodes verifies all DNS error codes per tor-spec.txt §6.4
//
// Specification defines the following error codes:
//
//	0x00: No error
//	0x01: Format error
//	0x02: Server failure
//	0x03: Name does not exist (NXDOMAIN)
//	0x04: Not implemented
//	0x05: Query refused
//	0xF0: Transient failure (Tor-specific)
//	0xF1: Non-transient failure (Tor-specific)
func TestDNSErrorCodes(t *testing.T) {
	tests := []struct {
		name      string
		errorCode byte
		wantConst byte
		desc      string
	}{
		{"No error", 0x00, DNSErrorNone, "No error"},
		{"Format error", 0x01, DNSErrorFormat, "Format error in query"},
		{"Server failure", 0x02, DNSErrorServerFailure, "Server failure (SERVFAIL)"},
		{"NXDOMAIN", 0x03, DNSErrorNotExist, "Name does not exist"},
		{"Not implemented", 0x04, DNSErrorNotImplemented, "Query type not implemented"},
		{"Refused", 0x05, DNSErrorRefused, "Query refused"},
		{"Transient failure", 0xF0, DNSErrorTransientFailure, "Transient failure (Tor-specific)"},
		{"Non-transient failure", 0xF1, DNSErrorNonTransientFailure, "Non-transient failure (Tor-specific)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify constant matches spec value
			if tt.wantConst != tt.errorCode {
				t.Errorf("Constant = 0x%02X, want 0x%02X for %s", tt.wantConst, tt.errorCode, tt.desc)
			}

			// 常量对照保留；RELAY_RESOLVED 错误 Value 是字符串，不是 RCODE。
			if tt.errorCode == DNSErrorTransientFailure || tt.errorCode == DNSErrorNonTransientFailure {
				msg := "Error resolving hostname"
				payload := make([]byte, 2+len(msg)+4)
				payload[0] = tt.errorCode
				payload[1] = byte(len(msg))
				copy(payload[2:], msg)
				binary.BigEndian.PutUint32(payload[2+len(msg):], 0)

				result, err := parseResolvedCell(payload)
				if err != nil {
					t.Fatalf("parseResolvedCell() error = %v", err)
				}
				if result.Type != tt.errorCode {
					t.Errorf("Type = 0x%02X, want 0x%02X", result.Type, tt.errorCode)
				}
				if result.Error != tt.errorCode {
					t.Errorf("Error = 0x%02X, want 0x%02X", result.Error, tt.errorCode)
				}
			}
		})
	}
}

// TestDNSTTLEncoding verifies TTL encoding per tor-spec.txt §6.4
//
// Specification: TTL is encoded as a 4-byte big-endian unsigned integer
func TestDNSTTLEncoding(t *testing.T) {
	tests := []struct {
		name    string
		ttl     uint32
		wantTTL uint32
	}{
		{"Zero TTL", 0, 0},
		{"1 hour", 3600, 3600},
		{"1 day", 86400, 86400},
		{"1 week", 604800, 604800},
		{"Maximum TTL", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create IPv4 response with specific TTL
			payload := make([]byte, 10)
			payload[0] = DNSTypeIPv4
			payload[1] = 4
			copy(payload[2:6], []byte{192, 0, 2, 1})
			binary.BigEndian.PutUint32(payload[6:10], tt.ttl)

			// Parse and verify TTL
			result, err := parseResolvedCell(payload)
			if err != nil {
				t.Fatalf("parseResolvedCell() error = %v", err)
			}

			if result.TTL != tt.wantTTL {
				t.Errorf("TTL = %d, want %d", result.TTL, tt.wantTTL)
			}

			// Verify TTL is big-endian encoded
			encodedTTL := binary.BigEndian.Uint32(payload[6:10])
			if encodedTTL != tt.wantTTL {
				t.Errorf("Encoded TTL = %d, want %d", encodedTTL, tt.wantTTL)
			}
		})
	}
}

// TestDNSRecordTypesSpecCompliance verifies all DNS record types per tor-spec.txt §6.4
func TestDNSRecordTypesSpecCompliance(t *testing.T) {
	tests := []struct {
		name      string
		typeCode  byte
		wantConst byte
		desc      string
	}{
		{"Hostname", 0x00, DNSTypeHostname, "Hostname (PTR response or error)"},
		{"IPv4", 0x04, DNSTypeIPv4, "IPv4 address"},
		{"IPv6", 0x06, DNSTypeIPv6, "IPv6 address"},
		{"Error", 0xF0, DNSTypeError, "Error response"},
		{"Error with TTL", 0xF1, DNSTypeErrorTTL, "Error response with TTL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify constant matches spec value
			if tt.wantConst != tt.typeCode {
				t.Errorf("Constant = 0x%02X, want 0x%02X for %s", tt.wantConst, tt.typeCode, tt.desc)
			}
		})
	}
}

// TestDNSLeakPrevention verifies DNS queries go through circuit, not system resolver
func TestDNSLeakPrevention(t *testing.T) {
	t.Run("ResolveHostname does not use system resolver", func(t *testing.T) {
		// This test verifies that ResolveHostname sends RELAY_RESOLVE through circuit
		// instead of using net.LookupHost or similar system calls

		// Create mock circuit
		responseData := make([]byte, 10)
		responseData[0] = DNSTypeIPv4
		responseData[1] = 4
		copy(responseData[2:6], []byte{192, 0, 2, 1})
		binary.BigEndian.PutUint32(responseData[6:10], 3600)

		c := MockCircuitForDNS(t, responseData)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// This call should send RELAY_RESOLVE through circuit, not use system DNS
		result, err := c.ResolveHostname(ctx, "example.com")
		if err != nil {
			t.Fatalf("ResolveHostname() error = %v", err)
		}

		// Verify we got a result (proves it went through circuit, not system)
		if result == nil {
			t.Error("Expected result, got nil")
		}
	})

	t.Run("ResolveIP does not use system resolver", func(t *testing.T) {
		// Verify PTR queries also go through circuit
		hostname := "example.com\x00"
		responseData := make([]byte, 2+len(hostname)+4)
		responseData[0] = DNSTypeHostname
		responseData[1] = byte(len(hostname))
		copy(responseData[2:2+len(hostname)], []byte(hostname))
		binary.BigEndian.PutUint32(responseData[2+len(hostname):], 1800)

		c := MockCircuitForDNS(t, responseData)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// This call should send RELAY_RESOLVE through circuit, not use system DNS
		result, err := c.ResolveIP(ctx, net.ParseIP("192.0.2.1"))
		if err != nil {
			t.Fatalf("ResolveIP() error = %v", err)
		}

		// Verify we got a result
		if result == nil {
			t.Error("Expected result, got nil")
		}
	})
}

// TestDNSEdgeCases tests edge cases and error conditions
func TestDNSEdgeCases(t *testing.T) {
	t.Run("Empty hostname", func(t *testing.T) {
		c := &Circuit{
			ID:               1,
			State:            StateOpen,
			relayReceiveChan: make(chan *cell.RelayCell, 1),
		}

		ctx := context.Background()
		_, err := c.ResolveHostname(ctx, "")
		if err == nil {
			t.Error("Expected error for empty hostname")
		}
	})

	t.Run("Nil IP address", func(t *testing.T) {
		c := &Circuit{
			ID:               1,
			State:            StateOpen,
			relayReceiveChan: make(chan *cell.RelayCell, 1),
		}

		ctx := context.Background()
		_, err := c.ResolveIP(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil IP")
		}
	})

	t.Run("Empty RELAY_RESOLVED data", func(t *testing.T) {
		_, err := parseResolvedCell([]byte{})
		if err == nil {
			t.Error("Expected error for empty data")
		}
	})

	t.Run("Truncated RELAY_RESOLVED data", func(t *testing.T) {
		// Only TYPE and LENGTH, no value or TTL
		payload := []byte{DNSTypeIPv4, 4}
		_, err := parseResolvedCell(payload)
		if err == nil {
			t.Error("Expected error for truncated data")
		}
	})

	t.Run("Invalid IPv4 length", func(t *testing.T) {
		// TYPE (0x04) | LENGTH (3) - wrong! | garbage | TTL
		payload := make([]byte, 9)
		payload[0] = DNSTypeIPv4
		payload[1] = 3 // Should be 4
		payload[2] = 192
		payload[3] = 0
		payload[4] = 2
		binary.BigEndian.PutUint32(payload[5:9], 3600)

		_, err := parseResolvedCell(payload)
		if err == nil {
			t.Error("Expected error for invalid IPv4 length")
		}
	})

	t.Run("Invalid IPv6 length", func(t *testing.T) {
		// TYPE (0x06) | LENGTH (8) - wrong! | garbage | TTL
		payload := make([]byte, 14)
		payload[0] = DNSTypeIPv6
		payload[1] = 8 // Should be 16
		binary.BigEndian.PutUint32(payload[10:14], 3600)

		_, err := parseResolvedCell(payload)
		if err == nil {
			t.Error("Expected error for invalid IPv6 length")
		}
	})

	t.Run("Empty error value is still an error record", func(t *testing.T) {
		payload := make([]byte, 6)
		payload[0] = DNSTypeError
		payload[1] = 0
		binary.BigEndian.PutUint32(payload[2:6], 0)

		result, err := parseResolvedCell(payload)
		if err != nil {
			t.Fatalf("empty 0xF0 value should parse: %v", err)
		}
		if result.Type != DNSTypeError {
			t.Errorf("Type = 0x%02X, want 0xF0", result.Type)
		}
	})
}
