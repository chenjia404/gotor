package directory

import (
	"net"
	"testing"
)

func TestParseExitPolicySummary(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		port    int
		allow   bool
		wantErr bool
	}{
		{name: "accept 80 and 443 allows 443", line: "p accept 80,443", port: 443, allow: true},
		{name: "accept 80 and 443 rejects 22", line: "p accept 80,443", port: 22, allow: false},
		{name: "reject list allows unlisted", line: "p reject 25,119,135-139", port: 443, allow: true},
		{name: "reject list blocks range", line: "p reject 25,119,135-139", port: 137, allow: false},
		{name: "reject all", line: "p reject 1-65535", port: 80, allow: false},
		{name: "accept all", line: "p accept 1-65535", port: 9050, allow: true},
		{name: "without p prefix", line: "accept 80,443", port: 80, allow: true},
		{name: "p6 accept", line: "p6 accept 80,443", port: 443, allow: true},
		{name: "p6 reject listed", line: "p6 reject 25,119", port: 25, allow: false},
		{name: "ipv6-policy accept", line: "ipv6-policy accept 80,443", port: 80, allow: true},
		{name: "empty", line: "", wantErr: true},
		{name: "bad verb", line: "p maybe 80", wantErr: true},
		{name: "bad port", line: "p accept 0", wantErr: true},
		{name: "inverted range", line: "p accept 443-80", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol, err := ParseExitPolicySummary(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := pol.Allows(tc.port); got != tc.allow {
				t.Fatalf("Allows(%d)=%v want %v", tc.port, got, tc.allow)
			}
		})
	}
}

func TestRelayCanExitToPort(t *testing.T) {
	flagOnly := &Relay{Flags: []string{"Exit"}}
	if !flagOnly.CanExitToPort(443) {
		t.Fatal("Exit flag without policy should allow heuristic selection")
	}
	if flagOnly.HasParsedPolicy() {
		t.Fatal("expected no parsed policy")
	}

	middle := &Relay{Flags: []string{"Fast"}}
	if middle.CanExitToPort(443) {
		t.Fatal("non-exit without policy must not be selected")
	}

	pol, err := ParseExitPolicySummary("p accept 80")
	if err != nil {
		t.Fatal(err)
	}
	httpOnly := &Relay{Flags: []string{"Exit"}, ExitPolicy: pol}
	if !httpOnly.HasParsedPolicy() {
		t.Fatal("expected parsed policy")
	}
	if !httpOnly.CanExitToPort(80) {
		t.Fatal("policy accept 80 should allow 80")
	}
	if httpOnly.CanExitToPort(443) {
		t.Fatal("Exit flag must not override parsed reject of 443")
	}
}

func TestRelayCanExitToIPv6UsesP6(t *testing.T) {
	v4, err := ParseExitPolicySummary("p accept 80,443")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := ParseExitPolicySummary("p6 accept 80")
	if err != nil {
		t.Fatal(err)
	}
	exit := &Relay{Flags: []string{"Exit"}, ExitPolicy: v4, ExitPolicyIPv6: v6}
	if !exit.HasParsedIPv6Policy() {
		t.Fatal("expected parsed p6")
	}
	if !exit.CanExitTo(net.ParseIP("192.0.2.1"), 443) {
		t.Fatal("IPv4 443 should follow p")
	}
	if exit.CanExitTo(net.ParseIP("2001:db8::1"), 443) {
		t.Fatal("IPv6 443 must follow p6, not IPv4 p")
	}
	if !exit.CanExitTo(net.ParseIP("2001:db8::1"), 80) {
		t.Fatal("p6 accept 80 should allow IPv6:80")
	}

	noP6 := &Relay{Flags: []string{"Exit"}, ExitPolicy: v4}
	if noP6.CanExitTo(net.ParseIP("2001:db8::1"), 80) {
		t.Fatal("missing p6 is reject 1-65535")
	}
	if !noP6.CanExitToPort(443) {
		t.Fatal("IPv4/hostname still uses p")
	}
	if noP6.CanExitTo(nil, 22) {
		t.Fatal("hostname 22 must follow p accept 80,443")
	}
	if noP6.CanExitTo(net.ParseIP("192.0.2.1"), 0) {
		t.Fatal("port 0 is never permitted")
	}

	// 仅有 IPv4 完整规则、无 p6：IPv6 仍拒绝（缺 p6 ≡ reject 1-65535）
	rules, _, err := ParseExitPolicyLines([]string{"accept *:*"})
	if err != nil {
		t.Fatal(err)
	}
	v4OnlyRules := &Relay{Flags: []string{"Exit"}, ExitRules: rules}
	if v4OnlyRules.CanExitTo(net.ParseIP("2001:db8::1"), 443) {
		t.Fatal("IPv4-only full policy must not imply IPv6 allow")
	}
}

func TestIPv4MappedUsesIPv4Policy(t *testing.T) {
	v4, err := ParseExitPolicySummary("p accept 443")
	if err != nil {
		t.Fatal(err)
	}
	r := &Relay{ExitPolicy: v4}
	mapped := net.ParseIP("::ffff:192.0.2.10")
	if !r.CanExitTo(mapped, 443) {
		t.Fatal("IPv4-mapped address must use IPv4 summary")
	}
	if r.CanExitTo(mapped, 80) {
		t.Fatal("IPv4-mapped 80 should be rejected by p accept 443")
	}
}
