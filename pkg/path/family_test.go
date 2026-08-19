// Package path family validation tests
package path

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

// TestRelayFamilyValidation tests bidirectional family relationship checking
func TestRelayFamilyValidation(t *testing.T) {
	tests := []struct {
		name     string
		relay1   *directory.Relay
		relay2   *directory.Relay
		expected bool
		desc     string
	}{
		{
			name: "same relay",
			relay1: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
			},
			relay2: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
			},
			expected: true,
			desc:     "Same relay should be considered in same family",
		},
		{
			name: "bidirectional family by fingerprint",
			relay1: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
				Family:      []string{"BBBB"},
			},
			relay2: &directory.Relay{
				Fingerprint: "BBBB",
				Nickname:    "relay2",
				Family:      []string{"AAAA"},
			},
			expected: true,
			desc:     "Bidirectional family relationship should be detected",
		},
		{
			name: "bidirectional family by nickname",
			relay1: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
				Family:      []string{"relay2"},
			},
			relay2: &directory.Relay{
				Fingerprint: "BBBB",
				Nickname:    "relay2",
				Family:      []string{"relay1"},
			},
			expected: true,
			desc:     "Family by nickname should work",
		},
		{
			name: "unidirectional family",
			relay1: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
				Family:      []string{"BBBB"},
			},
			relay2: &directory.Relay{
				Fingerprint: "BBBB",
				Nickname:    "relay2",
				Family:      []string{},
			},
			expected: false,
			desc:     "Unidirectional family should not be considered valid",
		},
		{
			name: "no family relationship",
			relay1: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
				Family:      []string{},
			},
			relay2: &directory.Relay{
				Fingerprint: "BBBB",
				Nickname:    "relay2",
				Family:      []string{},
			},
			expected: false,
			desc:     "No family relationship should return false",
		},
		{
			name: "different relays no family declared",
			relay1: &directory.Relay{
				Fingerprint: "AAAA",
				Nickname:    "relay1",
			},
			relay2: &directory.Relay{
				Fingerprint: "BBBB",
				Nickname:    "relay2",
			},
			expected: false,
			desc:     "Different relays with nil family should not be in same family",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.relay1.InSameFamily(tt.relay2)
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.desc, tt.expected, result)
			}

			// Test symmetry
			reverseResult := tt.relay2.InSameFamily(tt.relay1)
			if reverseResult != result {
				t.Errorf("Family check not symmetric: relay1->relay2=%v, relay2->relay1=%v",
					result, reverseResult)
			}
		})
	}
}

// TestRelaySubnetValidation tests /16 subnet checking
func TestRelaySubnetValidation(t *testing.T) {
	tests := []struct {
		name     string
		relay1   *directory.Relay
		relay2   *directory.Relay
		expected bool
		desc     string
	}{
		{
			name: "same /16 subnet",
			relay1: &directory.Relay{
				Address: "192.168.1.1",
			},
			relay2: &directory.Relay{
				Address: "192.168.2.1",
			},
			expected: true,
			desc:     "Relays in same /16 subnet should be detected",
		},
		{
			name: "different /16 subnet",
			relay1: &directory.Relay{
				Address: "192.168.1.1",
			},
			relay2: &directory.Relay{
				Address: "10.0.1.1",
			},
			expected: false,
			desc:     "Relays in different /16 subnets should not match",
		},
		{
			name: "same IP address",
			relay1: &directory.Relay{
				Address: "192.168.1.1",
			},
			relay2: &directory.Relay{
				Address: "192.168.1.1",
			},
			expected: true,
			desc:     "Same IP address should be in same subnet",
		},
		{
			name: "different second octet",
			relay1: &directory.Relay{
				Address: "192.168.1.1",
			},
			relay2: &directory.Relay{
				Address: "192.169.1.1",
			},
			expected: false,
			desc:     "Different second octet means different /16 subnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.relay1.InSameSubnet(tt.relay2)
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.desc, tt.expected, result)
			}

			// Test symmetry
			reverseResult := tt.relay2.InSameSubnet(tt.relay1)
			if reverseResult != result {
				t.Errorf("Subnet check not symmetric: relay1->relay2=%v, relay2->relay1=%v",
					result, reverseResult)
			}
		})
	}
}

// TestPathSelectionWithFamilyConstraints tests that path selection enforces family constraints
func TestPathSelectionWithFamilyConstraints(t *testing.T) {
	// Create relays with family relationships
	guard := &directory.Relay{
		Fingerprint: "GUARD1",
		Nickname:    "GuardRelay",
		Address:     "192.168.1.1",
		ORPort:      9001,
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
		Family:      []string{"MIDDLE1"}, // Guard is in family with middle
	}

	middle1 := &directory.Relay{
		Fingerprint: "MIDDLE1",
		Nickname:    "MiddleRelay1",
		Address:     "192.168.1.2", // Same /16 subnet as guard
		ORPort:      9001,
		Flags:       []string{"Running", "Valid", "Fast"},
		Family:      []string{"GUARD1"}, // Bidirectional family with guard
	}

	middle2 := &directory.Relay{
		Fingerprint: "MIDDLE2",
		Nickname:    "MiddleRelay2",
		Address:     "10.0.1.1", // Different /16 subnet
		ORPort:      9001,
		Flags:       []string{"Running", "Valid", "Fast"},
		Family:      []string{}, // No family relationship
	}

	exit := &directory.Relay{
		Fingerprint: "EXIT1",
		Nickname:    "ExitRelay",
		Address:     "172.16.1.1",
		ORPort:      9001,
		Flags:       []string{"Exit", "Running", "Valid", "Fast"},
		Family:      []string{},
	}

	// Test family detection
	if !guard.InSameFamily(middle1) {
		t.Error("Guard and Middle1 should be in same family")
	}

	if guard.InSameFamily(middle2) {
		t.Error("Guard and Middle2 should not be in same family")
	}

	// Test subnet detection
	if !guard.InSameSubnet(middle1) {
		t.Error("Guard and Middle1 should be in same subnet")
	}

	if guard.InSameSubnet(middle2) {
		t.Error("Guard and Middle2 should not be in same subnet")
	}

	// Test that middle2 is valid choice but middle1 is not
	_ = exit // Suppress unused warning
	if middle1.InSameFamily(guard) || middle1.InSameSubnet(guard) {
		t.Log("Middle1 correctly identified as invalid (family/subnet conflict)")
	}

	if middle2.InSameFamily(guard) || middle2.InSameSubnet(guard) {
		t.Error("Middle2 should be valid choice (no family/subnet conflict)")
	}
}

func TestSelectMiddleAvoidsSharedFamilyID(t *testing.T) {
	guard := &directory.Relay{
		Fingerprint: "G1",
		Nickname:    "g",
		Address:     "198.51.100.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
		FamilyIDs:   []string{"ed25519:SHAREDKEY"},
	}
	bad := &directory.Relay{
		Fingerprint: "M1",
		Nickname:    "bad",
		Address:     "203.0.113.1",
		Flags:       []string{"Running", "Valid", "Fast"},
		FamilyIDs:   []string{"ed25519:SHAREDKEY"},
	}
	good := &directory.Relay{
		Fingerprint: "M2",
		Nickname:    "good",
		Address:     "192.0.2.1",
		Flags:       []string{"Running", "Valid", "Fast"},
		FamilyIDs:   []string{"ed25519:OTHER"},
	}
	exit := &directory.Relay{
		Fingerprint: "E1",
		Nickname:    "e",
		Address:     "172.16.0.8",
		Flags:       []string{"Exit", "Running", "Valid", "Fast"},
	}

	s := NewSelector(directory.NewClient(nil), nil)
	s.relays = []*directory.Relay{guard, bad, good, exit}

	got, err := s.selectMiddle(guard, exit)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "M2" {
		t.Fatalf("middle = %s, 应避开共享 family-ids 的 M1", got.Fingerprint)
	}
}

func TestPathHopsShareFamily(t *testing.T) {
	shared := []string{"ed25519:SHAREDKEY"}
	g := &directory.Relay{Fingerprint: "G", FamilyIDs: shared}
	mOK := &directory.Relay{Fingerprint: "M", FamilyIDs: []string{"ed25519:OTHER"}}
	mBad := &directory.Relay{Fingerprint: "MB", FamilyIDs: shared}
	e := &directory.Relay{Fingerprint: "E"}

	if PathHopsShareFamily(nil, &Path{Guard: g, Middle: mOK, Exit: e}) {
		t.Fatal("不同 family-ids 不得判为同家族")
	}
	if !PathHopsShareFamily(nil, &Path{Guard: g, Middle: mBad, Exit: e}) {
		t.Fatal("Guard/Middle 共享 family-ids 必须重选")
	}
	if PathHopsShareFamily(nil, nil) {
		t.Fatal("nil path 不得判为同家族")
	}
}

func TestConfluxLegsShareFamily(t *testing.T) {
	id := []string{"ed25519:LEGSHARE"}
	first := &Path{
		Guard:  &directory.Relay{Fingerprint: "G1", FamilyIDs: id},
		Middle: &directory.Relay{Fingerprint: "M1"},
		Exit:   &directory.Relay{Fingerprint: "E"},
	}
	ok := &Path{
		Guard:  &directory.Relay{Fingerprint: "G2", FamilyIDs: []string{"ed25519:OTHER"}},
		Middle: &directory.Relay{Fingerprint: "M2"},
		Exit:   first.Exit,
	}
	bad := &Path{
		Guard:  &directory.Relay{Fingerprint: "G3", FamilyIDs: id},
		Middle: &directory.Relay{Fingerprint: "M3"},
		Exit:   first.Exit,
	}
	if ConfluxLegsShareFamily(nil, first, ok) {
		t.Fatal("不同 family-ids 的第二腿不得判冲突")
	}
	if !ConfluxLegsShareFamily(nil, first, bad) {
		t.Fatal("第二腿 Guard 与第一腿 Guard 共享 family-ids 必须冲突")
	}
	// 共享 Exit 本身不是家族冲突。
	sameExitOnly := &Path{
		Guard:  &directory.Relay{Fingerprint: "G4"},
		Middle: &directory.Relay{Fingerprint: "M4"},
		Exit:   first.Exit,
	}
	if ConfluxLegsShareFamily(nil, first, sameExitOnly) {
		t.Fatal("仅共享 Exit 不得视为两腿家族冲突")
	}
}
