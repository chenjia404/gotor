package directory

import (
	"net"
	"testing"
)

func TestParseExitPolicyLinesFirstMatch(t *testing.T) {
	pol, ipv6, err := ParseExitPolicyLines([]string{
		"reject 0.0.0.0/8:*",
		"reject *:25",
		"accept *:80",
		"accept *:443",
		"reject *:*",
		"ipv6-policy accept 80,443",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pol == nil || ipv6 == nil {
		t.Fatal("expected rules and ipv6-policy")
	}
	if !pol.Allows(net.ParseIP("8.8.8.8"), 443) {
		t.Fatal("accept *:443 should allow public IPv4:443")
	}
	if pol.Allows(net.ParseIP("8.8.8.8"), 25) {
		t.Fatal("reject *:25")
	}
	if pol.Allows(net.ParseIP("0.1.2.3"), 80) {
		t.Fatal("reject 0.0.0.0/8 comes first")
	}
	if !ipv6.Allows(443) || ipv6.Allows(22) {
		t.Fatal("ipv6-policy accept 80,443")
	}
}

func TestExitPolicyNoMatchAccepts(t *testing.T) {
	pol, _, err := ParseExitPolicyLines([]string{"reject *:25"})
	if err != nil {
		t.Fatal(err)
	}
	if !pol.Allows(net.ParseIP("1.2.3.4"), 443) {
		t.Fatal("dir-spec: no matching rule accepts")
	}
}

func TestExitPolicyStarIsIPv4Only(t *testing.T) {
	pol, _, err := ParseExitPolicyLines([]string{"reject *:*"})
	if err != nil {
		t.Fatal(err)
	}
	if pol.Allows(net.ParseIP("1.2.3.4"), 80) {
		t.Fatal("reject *:* must reject IPv4")
	}
	if !pol.Allows(net.ParseIP("2001:db8::1"), 80) {
		t.Fatal("* is IPv4-only; IPv6 should not match this rule, so no-match accepts")
	}
	if pol.hasIPv6Rule() {
		t.Fatal("reject *:* is not an IPv6 rule")
	}
}

func TestExitPolicyIPv6Addrspec(t *testing.T) {
	pol, _, err := ParseExitPolicyLines([]string{
		"accept [2001:db8::]/32:80-443",
		"reject *6:*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pol.hasIPv6Rule() {
		t.Fatal("expected IPv6 rules")
	}
	if !pol.Allows(net.ParseIP("2001:db8::aa"), 443) {
		t.Fatal("prefix should allow")
	}
	if pol.Allows(net.ParseIP("2001:db9::1"), 443) {
		t.Fatal("outside prefix then reject *6")
	}
	if !pol.Allows(net.ParseIP("8.8.8.8"), 443) {
		t.Fatal("IPv4 does not match IPv6 rules; no-match accepts")
	}
}

func TestExitPolicyDottedMaskAndHostBits(t *testing.T) {
	pol, _, err := ParseExitPolicyLines([]string{
		"reject 127.0.0.1/8:*",
		"accept 192.168.1.0/255.255.255.0:80",
		"reject *:*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pol.Allows(net.ParseIP("127.1.2.3"), 80) {
		t.Fatal("host bits in 127.0.0.1/8 must still match the /8")
	}
	if !pol.Allows(net.ParseIP("192.168.1.9"), 80) {
		t.Fatal("dotted mask /24 should allow")
	}
	if pol.Allows(net.ParseIP("192.168.2.9"), 80) {
		t.Fatal("outside dotted mask")
	}
}

func TestExitPolicyPortZeroNeverAllowed(t *testing.T) {
	pol, _, err := ParseExitPolicyLines([]string{"accept *:0", "accept *:*"})
	if err != nil {
		t.Fatal(err)
	}
	if pol.Allows(net.ParseIP("1.2.3.4"), 0) {
		t.Fatal("connections to port 0 are never permitted")
	}
}

func TestExitPolicyAllowsUnknown(t *testing.T) {
	pol, _, err := ParseExitPolicyLines([]string{
		"reject *:25",
		"accept *:80",
		"reject 8.8.8.8:*",
		"reject *:*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pol.AllowsUnknown(80) {
		t.Fatal("wildcard accept *:80 decides hostname")
	}
	if pol.AllowsUnknown(25) {
		t.Fatal("wildcard reject *:25")
	}
	if pol.AllowsUnknown(443) {
		t.Fatal("wildcard reject *:*")
	}

	addrOnly, _, err := ParseExitPolicyLines([]string{
		"accept 1.2.3.4:443",
		"reject 5.6.7.8:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !addrOnly.AllowsUnknown(443) {
		t.Fatal("address-specific accept is probably-accepted")
	}
}

func TestRelayFullRulesPreferOverSummary(t *testing.T) {
	summary, err := ParseExitPolicySummary("p accept 80,443")
	if err != nil {
		t.Fatal(err)
	}
	rules, _, err := ParseExitPolicyLines([]string{"reject *:443", "accept *:80", "reject *:*"})
	if err != nil {
		t.Fatal(err)
	}
	r := &Relay{Flags: []string{"Exit"}, ExitPolicy: summary, ExitRules: rules}
	if r.CanExitToPort(443) {
		t.Fatal("full rules must override p for hostname/IPv4")
	}
	if !r.CanExitTo(net.ParseIP("9.9.9.9"), 80) {
		t.Fatal("full rules accept *:80")
	}
}

func TestParseExitPolicyLinesErrors(t *testing.T) {
	if _, _, err := ParseExitPolicyLines(nil); err == nil {
		t.Fatal("empty must fail")
	}
	if _, _, err := ParseExitPolicyLines([]string{"accept"}); err == nil {
		t.Fatal("missing pattern")
	}
	if _, _, err := ParseExitPolicyLines([]string{"accept [2001:db8::1:80"}); err == nil {
		t.Fatal("unclosed IPv6")
	}
	if _, _, err := ParseExitPolicyLines([]string{"foo *:*"}); err == nil {
		t.Fatal("unknown verb")
	}
}
