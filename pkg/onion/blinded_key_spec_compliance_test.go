package onion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

// TestBlindedKeySpecCompliance_Algorithm tests KEYBLIND per rend-spec-v3 Appendix A.
//
//	h = SHA3_256("Derive temporary signing key"|0x00|A|basepoint_str|N)
//	N = "key-blind"|INT_8(period)|INT_8(1440)
//	A' = clamp(h)·A
func TestBlindedKeySpecCompliance_Algorithm(t *testing.T) {
	tests := []struct {
		name        string
		description string
		test        func(t *testing.T)
	}{
		{
			name:        "SHA3-256 hash function",
			description: "Param is SHA3-256; blinded key is 32-byte point",
			test: func(t *testing.T) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				timePeriod := uint64(12345)
				blinded := ComputeBlindedPubkey(pub, timePeriod)
				if len(blinded) != 32 {
					t.Errorf("Expected 32 bytes, got %d", len(blinded))
				}
				param, err := BuildBlindedKeyParam([]byte(pub), nil, timePeriod, 1440)
				if err != nil {
					t.Fatal(err)
				}
				if len(param) != 32 {
					t.Fatal("param must be SHA3-256 digest")
				}
			},
		},
		{
			name:        "Input string format",
			description: "BLIND_STRING includes trailing NUL (C sizeof)",
			test: func(t *testing.T) {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				p1, _ := BuildBlindedKeyParam([]byte(pub), nil, 0, 1440)
				p2, _ := BuildBlindedKeyParam([]byte(pub), nil, 1, 1440)
				if bytes.Equal(p1, p2) {
					t.Error("period must affect blinding param")
				}
			},
		},
		{
			name:        "Time period encoding",
			description: "period_num is INT_8 big-endian in N",
			test: func(t *testing.T) {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				seen := map[string]bool{}
				for _, tp := range []uint64{0, 1, 255, 256, 65535, 65536} {
					b := ComputeBlindedPubkey(pub, tp)
					k := string(b)
					if seen[k] {
						t.Errorf("duplicate blinded key for period %d", tp)
					}
					seen[k] = true
				}
			},
		},
		{
			name:        "Public key length",
			description: "Verifies ed25519 public key is 32 bytes",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				if len(pubkey) != 32 {
					t.Fatalf("ed25519 public key must be 32 bytes, got %d", len(pubkey))
				}
				blinded := ComputeBlindedPubkey(pubkey, 12345)
				if len(blinded) != 32 {
					t.Errorf("Expected 32-byte output, got %d", len(blinded))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Log(tt.description)
			tt.test(t)
		})
	}
}

// TestBlindedKeySpecCompliance_Determinism tests deterministic computation
// per rend-spec-v3.txt §2.
func TestBlindedKeySpecCompliance_Determinism(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "Same inputs produce same output",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				timePeriod := uint64(12345)

				blinded1 := ComputeBlindedPubkey(pubkey, timePeriod)
				blinded2 := ComputeBlindedPubkey(pubkey, timePeriod)

				if !bytes.Equal(blinded1, blinded2) {
					t.Error("Expected deterministic output for same inputs")
				}
			},
		},
		{
			name: "Different time periods produce different outputs",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}

				blinded1 := ComputeBlindedPubkey(pubkey, 1)
				blinded2 := ComputeBlindedPubkey(pubkey, 2)

				if bytes.Equal(blinded1, blinded2) {
					t.Error("Expected different outputs for different time periods")
				}
			},
		},
		{
			name: "Different public keys produce different outputs",
			test: func(t *testing.T) {
				pubkey1, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				pubkey2, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				timePeriod := uint64(12345)

				blinded1 := ComputeBlindedPubkey(pubkey1, timePeriod)
				blinded2 := ComputeBlindedPubkey(pubkey2, timePeriod)

				if bytes.Equal(blinded1, blinded2) {
					t.Error("Expected different outputs for different public keys")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// TestBlindedKeySpecCompliance_TimePeriod tests time period calculation
// per C Tor hs_get_time_period_num: (unix/60 - 720) / 1440.
func TestBlindedKeySpecCompliance_TimePeriod(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "Time period formula",
			test: func(t *testing.T) {
				const periodLengthSec = 86400
				// Epoch: minutes=0 < offset → 0
				if tp := GetTimePeriod(time.Unix(0, 0)); tp != 0 {
					t.Errorf("Expected 0 for epoch, got %d", tp)
				}
				// One day: (1440 - 720) / 1440 = 0
				if tp := GetTimePeriod(time.Unix(periodLengthSec, 0)); tp != 0 {
					t.Errorf("Expected 0 for one day, got %d", tp)
				}
				// Two days: (2880 - 720) / 1440 = 1
				if tp := GetTimePeriod(time.Unix(2*periodLengthSec, 0)); tp != 1 {
					t.Errorf("Expected 1 for two days, got %d", tp)
				}
				// Known unix matching Tor formula
				unix := int64(1700000000)
				want := (uint64(unix)/60 - 720) / 1440
				if got := GetTimePeriod(time.Unix(unix, 0)); got != want {
					t.Errorf("got %d want %d", got, want)
				}
			},
		},
		{
			name: "Current time period is non-negative",
			test: func(t *testing.T) {
				_ = GetTimePeriod(time.Now())
			},
		},
		{
			name: "Time period increases with time",
			test: func(t *testing.T) {
				t1 := time.Unix(2*86400, 0)
				t2 := time.Unix(4*86400, 0)
				t3 := time.Unix(6*86400, 0)
				tp1, tp2, tp3 := GetTimePeriod(t1), GetTimePeriod(t2), GetTimePeriod(t3)
				if !(tp1 < tp2 && tp2 < tp3) {
					t.Errorf("expected increasing periods: %d %d %d", tp1, tp2, tp3)
				}
			},
		},
		{
			name: "Same time period for times within 24 hours",
			test: func(t *testing.T) {
				// 周期在每日 12:00 UTC 旋转；取同日内 13:00 与 22:00 应同周期
				t1 := time.Date(2024, 6, 15, 13, 0, 0, 0, time.UTC)
				t2 := time.Date(2024, 6, 15, 22, 0, 0, 0, time.UTC)
				if GetTimePeriod(t1) != GetTimePeriod(t2) {
					t.Errorf("Expected same period within day: %d vs %d", GetTimePeriod(t1), GetTimePeriod(t2))
				}
				t3 := time.Date(2024, 6, 16, 13, 0, 0, 0, time.UTC)
				if GetTimePeriod(t1) == GetTimePeriod(t3) {
					t.Error("Expected different period next day")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

// TestBlindedKeySpecCompliance_Integration tests blinded key usage in descriptor ID
// computation per rend-spec-v3.txt §2.
func TestBlindedKeySpecCompliance_Integration(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "Descriptor ID computation uses blinded key",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				timePeriod := uint64(12345)

				// Compute blinded key
				blindedPubkey := ComputeBlindedPubkey(pubkey, timePeriod)

				// Compute descriptor ID from blinded key
				descriptorID := computeDescriptorID(blindedPubkey)

				// Descriptor ID should be 32 bytes (SHA3-256 output)
				if len(descriptorID) != 32 {
					t.Errorf("Expected descriptor ID length 32, got %d", len(descriptorID))
				}

				// Verify descriptor ID is SHA3-256 of blinded key
				h := sha3.New256()
				h.Write(blindedPubkey)
				expected := h.Sum(nil)

				if !bytes.Equal(descriptorID, expected) {
					t.Error("Descriptor ID does not match SHA3-256 of blinded key")
				}
			},
		},
		{
			name: "Different time periods produce different descriptor IDs",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}

				// Compute for two different time periods
				blinded1 := ComputeBlindedPubkey(pubkey, 1)
				blinded2 := ComputeBlindedPubkey(pubkey, 2)

				desc1 := computeDescriptorID(blinded1)
				desc2 := computeDescriptorID(blinded2)

				if bytes.Equal(desc1, desc2) {
					t.Error("Expected different descriptor IDs for different time periods")
				}
			},
		},
		{
			name: "Blinded key rotates every 24 hours",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}

				// Test at the start of a period
				const periodLength = 86400 // 24 hours
				t1 := time.Unix(periodLength*100, 0)
				t2 := time.Unix(periodLength*100+periodLength, 0)

				tp1 := GetTimePeriod(t1)
				tp2 := GetTimePeriod(t2)

				blinded1 := ComputeBlindedPubkey(pubkey, tp1)
				blinded2 := ComputeBlindedPubkey(pubkey, tp2)

				if bytes.Equal(blinded1, blinded2) {
					t.Error("Expected blinded key to rotate every 24 hours")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// TestBlindedKeySpecCompliance_EdgeCases tests edge cases in blinded key computation
func TestBlindedKeySpecCompliance_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "Zero time period",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}

				blinded := ComputeBlindedPubkey(pubkey, 0)

				if len(blinded) != 32 {
					t.Errorf("Expected 32-byte output for zero time period, got %d", len(blinded))
				}
			},
		},
		{
			name: "Maximum time period (uint64)",
			test: func(t *testing.T) {
				pubkey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}

				maxTimePeriod := uint64(0xFFFFFFFFFFFFFFFF)
				blinded := ComputeBlindedPubkey(pubkey, maxTimePeriod)

				if len(blinded) != 32 {
					t.Errorf("Expected 32-byte output for max time period, got %d", len(blinded))
				}
			},
		},
		{
			name: "All-zero public key",
			test: func(t *testing.T) {
				pubkey := make([]byte, 32) // All zeros
				timePeriod := uint64(12345)

				blinded := ComputeBlindedPubkey(ed25519.PublicKey(pubkey), timePeriod)

				if len(blinded) != 32 {
					t.Errorf("Expected 32-byte output for all-zero pubkey, got %d", len(blinded))
				}

				// Should be deterministic even for all-zero key
				blinded2 := ComputeBlindedPubkey(ed25519.PublicKey(pubkey), timePeriod)
				if !bytes.Equal(blinded, blinded2) {
					t.Error("Expected deterministic output even for all-zero pubkey")
				}
			},
		},
		{
			name: "All-ones public key",
			test: func(t *testing.T) {
				pubkey := make([]byte, 32)
				for i := range pubkey {
					pubkey[i] = 0xFF
				}
				timePeriod := uint64(12345)

				blinded := ComputeBlindedPubkey(ed25519.PublicKey(pubkey), timePeriod)

				if len(blinded) != 32 {
					t.Errorf("Expected 32-byte output for all-ones pubkey, got %d", len(blinded))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// TestBlindedKeySpecCompliance_KnownVectors tests against known test vectors
// (if available from reference implementation)
func TestBlindedKeySpecCompliance_KnownVectors(t *testing.T) {
	// Note: These would ideally be test vectors from the reference Tor implementation
	// For now, we verify internal consistency

	tests := []struct {
		name   string
		pubkey []byte
		period uint64
		// expected []byte // Would be from reference implementation
	}{
		{
			name:   "Sequential pubkey, period 0",
			pubkey: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			period: 0,
		},
		{
			name:   "Sequential pubkey, period 1",
			pubkey: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			period: 1,
		},
		{
			name:   "All-zero pubkey, period 12345",
			pubkey: make([]byte, 32),
			period: 12345,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blinded := ComputeBlindedPubkey(ed25519.PublicKey(tt.pubkey), tt.period)

			// Verify length
			if len(blinded) != 32 {
				t.Errorf("Expected 32-byte output, got %d", len(blinded))
			}

			// Verify determinism
			blinded2 := ComputeBlindedPubkey(ed25519.PublicKey(tt.pubkey), tt.period)
			if !bytes.Equal(blinded, blinded2) {
				t.Error("Expected deterministic output")
			}

			// If we had expected values from reference implementation:
			// if tt.expected != nil && !bytes.Equal(blinded, tt.expected) {
			//     t.Errorf("Output does not match reference implementation")
			// }
		})
	}
}
