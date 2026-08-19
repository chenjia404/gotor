package control

import (
	"testing"
)

func TestKnownEventTypesIncludesNew(t *testing.T) {
	got := KnownEventTypes()
	need := map[EventType]bool{
		EventAddrMap: false, EventStatusClient: false, EventNotice: false,
		EventCirc: false, EventStream: false, EventBW: false,
	}
	for _, e := range got {
		if _, ok := need[e]; ok {
			need[e] = true
		}
	}
	for e, ok := range need {
		if !ok {
			t.Fatalf("missing event type %s", e)
		}
	}
}

func TestAddrMapAndStatusClientFormat(t *testing.T) {
	a := &AddrMapEvent{Address: "1.2.3.4", NewAddress: "5.6.7.8", Expiry: "NEVER"}
	if got := a.Format(); got != "650 ADDRMAP 1.2.3.4 5.6.7.8 NEVER" {
		t.Fatal(got)
	}
	s := &StatusClientEvent{Severity: "NOTICE", Action: "CIRCUIT_ESTABLISHED"}
	if got := s.Format(); got != "650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED" {
		t.Fatal(got)
	}
	n := &NoticeEvent{Message: "hello"}
	if got := n.Format(); got != "650 NOTICE hello" {
		t.Fatal(got)
	}
}
