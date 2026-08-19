package circuit

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestSubprotoCapsForDoesNotRequestCGO(t *testing.T) {
	r := &directory.Relay{
		Protocols: directory.ParseProtoLine("pr Relay=4-6 FlowCtrl=1-2"),
	}
	caps, err := subprotoCapsFor(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 0 {
		t.Fatalf("生产路径不得请求未实现的 CGO: %#v", caps)
	}
	if caps, err := subprotoCapsFor(nil); err != nil || caps != nil {
		t.Fatalf("nil relay: %v %#v", err, caps)
	}
}
