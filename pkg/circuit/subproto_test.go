package circuit

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestSubprotoCapsForRequestsCGOWhenPeerReady(t *testing.T) {
	r := &directory.Relay{
		Protocols: directory.ParseProtoLine("pr Relay=4-6 FlowCtrl=1-2"),
	}
	caps, err := subprotoCapsFor(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 1 || caps[0].Cap != 6 {
		t.Fatalf("对端 Relay=5-6 + FlowCtrl=2 应请求 CGO: %#v", caps)
	}
	r2 := &directory.Relay{Protocols: directory.ParseProtoLine("pr Relay=2-4 FlowCtrl=1")}
	caps, err = subprotoCapsFor(r2)
	if err != nil || len(caps) != 0 {
		t.Fatalf("无 Relay=5/6 不得请求: %v %#v", err, caps)
	}
	if caps, err := subprotoCapsFor(nil); err != nil || caps != nil {
		t.Fatalf("nil relay: %v %#v", err, caps)
	}
}
