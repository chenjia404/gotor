package client

import (
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/control"
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
