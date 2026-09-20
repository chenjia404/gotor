package client

import (
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/control"
	"github.com/opd-ai/go-tor/pkg/stream"
)

func TestControlCircuitPathSkipsHSHop(t *testing.T) {
	fp := "AABBCCDDEEFF00112233445566778899AABBCCDD"
	hops := []*circuit.Hop{
		{Fingerprint: fp},
		{Fingerprint: "hs-rendezvous"},
	}
	nicks := map[string]string{fp: "GuardNick"}
	got := controlCircuitPath(hops, nicks)
	want := control.LongName(fp, "GuardNick")
	if got != want {
		t.Fatalf("%s", got)
	}
}

func TestControlCircuitMeta(t *testing.T) {
	st, flags, purpose := controlCircuitMeta(circuit.StateOpen, []*circuit.Hop{{}, {}, {}})
	if st != "BUILT" || flags != "NEED_CAPACITY" || purpose != "GENERAL" {
		t.Fatalf("%s %s %s", st, flags, purpose)
	}
	st, flags, purpose = controlCircuitMeta(circuit.StateOpen, []*circuit.Hop{{Fingerprint: "hs-rendezvous"}})
	if st != "BUILT" || purpose != "HS_CLIENT_REND" || !strings.Contains(flags, "IS_INTERNAL") {
		t.Fatalf("%s %s %s", st, flags, purpose)
	}
	st, _, _ = controlCircuitMeta(circuit.StateBuilding, nil)
	if st != "LAUNCHED" {
		t.Fatalf("%s", st)
	}
}

func TestControlStreamMetaAndTarget(t *testing.T) {
	st, purpose := controlStreamMeta(stream.StateConnecting, "example.com")
	if st != "SENTCONNECT" || purpose != "USER" {
		t.Fatalf("%s %s", st, purpose)
	}
	st, purpose = controlStreamMeta(stream.StateConnected, "abc.onion")
	if st != "SUCCEEDED" || purpose != "HS_CLIENT" {
		t.Fatalf("%s %s", st, purpose)
	}
	if controlStreamTarget("example.com", 80) != "example.com:80" {
		t.Fatal(controlStreamTarget("example.com", 80))
	}
	if controlStreamTarget("2001:db8::1", 443) != "[2001:db8::1]:443" {
		t.Fatal(controlStreamTarget("2001:db8::1", 443))
	}
	st, _ = controlStreamMeta(stream.StateClosed, "x")
	if st != "" {
		t.Fatal("closed streams must not appear")
	}
}
