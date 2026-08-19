package socks

import (
	"context"
	"net"
	"testing"

	"github.com/opd-ai/go-tor/pkg/circuit"
)

type allowAllSOCKSExit struct{}

func (allowAllSOCKSExit) AllowsExit(net.IP, int) bool { return true }

func TestReplaceIfExitRejected(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1")
	reject := circuit.NewCircuit(1)
	reject.SetState(circuit.StateOpen)
	if _, err := replaceIfExitRejected(context.Background(), reject, v6, 443, nil, nil, nil); err == nil {
		t.Fatal("IPv6 without filter or builder must fail")
	}

	accept := circuit.NewCircuit(2)
	accept.SetState(circuit.StateOpen)
	accept.SetExitFilter(allowAllSOCKSExit{})
	got, err := replaceIfExitRejected(context.Background(), accept, v6, 443, nil, nil, nil)
	if err != nil || got != accept {
		t.Fatalf("allowing circuit should be kept: %v", err)
	}

	built := circuit.NewCircuit(3)
	built.SetState(circuit.StateOpen)
	built.SetExitFilter(allowAllSOCKSExit{})
	iso := circuit.NewIsolationKey(circuit.IsolationDestination)
	iso.Destination = "[2001:db8::1]:443"
	got, err = replaceIfExitRejected(context.Background(), reject, v6, 443, nil, func(context.Context, net.IP, int) (*circuit.Circuit, error) {
		return built, nil
	}, iso)
	if err != nil || got != built {
		t.Fatalf("builder should replace rejecting circuit: %v", err)
	}
	if got.GetIsolationKey() != iso {
		t.Fatal("replaced circuit must inherit isolation key")
	}
}
