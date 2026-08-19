package circuit

import (
	"net"
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

var _ ExitFilter = (*directory.Relay)(nil)

type stubExitFilter struct {
	allow bool
}

func (s stubExitFilter) AllowsExit(net.IP, int) bool { return s.allow }

func TestCircuitAllowsExitNilFilter(t *testing.T) {
	c := NewCircuit(1)
	if !c.AllowsExit(net.ParseIP("192.0.2.1"), 443) {
		t.Fatal("nil filter should allow IPv4 for test stubs")
	}
	if !c.AllowsExit(nil, 80) {
		t.Fatal("nil filter should allow hostname")
	}
	if c.AllowsExit(net.ParseIP("2001:db8::1"), 443) {
		t.Fatal("nil filter must reject IPv6 (missing p6)")
	}
	if c.AllowsExit(net.ParseIP("192.0.2.1"), 0) {
		t.Fatal("port 0 never allowed")
	}
}

func TestCircuitSetExitFilter(t *testing.T) {
	c := NewCircuit(2)
	c.SetExitFilter(stubExitFilter{allow: false})
	if c.AllowsExit(net.ParseIP("192.0.2.1"), 443) {
		t.Fatal("filter reject must win")
	}
	c.SetExitFilter(stubExitFilter{allow: true})
	if !c.AllowsExit(net.ParseIP("2001:db8::1"), 443) {
		t.Fatal("filter accept must win for IPv6")
	}
}
