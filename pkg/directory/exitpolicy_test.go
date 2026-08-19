package directory

import "testing"

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
