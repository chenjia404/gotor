package crypto

import (
	"bytes"
	"testing"
)

func TestEncodeSubprotoRequestRelay6(t *testing.T) {
	raw, err := EncodeSubprotoRequest([]SubprotoCap{{ProtocolID: ProtoRelay, Cap: CapRelayCGO}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x02, 0x06}) {
		t.Fatalf("Relay=6 must encode as [02 06], got %x", raw)
	}
}

func TestEncodeSubprotoRequestSorts(t *testing.T) {
	raw, err := EncodeSubprotoRequest([]SubprotoCap{
		{ProtocolID: ProtoRelay, Cap: CapRelayCGO},
		{ProtocolID: ProtoLinkAuth, Cap: 1},
	})
	// LinkAuth=1 不在现行协商表，必须拒绝，不能为了排序而发出未登记能力。
	if err == nil {
		t.Fatalf("non-negotiable cap must be rejected, got %x", raw)
	}
}

func TestEncodeSubprotoRequestRejectsEmptyDuplicateAndUnknown(t *testing.T) {
	if _, err := EncodeSubprotoRequest(nil); err == nil {
		t.Fatal("empty request must fail")
	}
	cgo := SubprotoCap{ProtocolID: ProtoRelay, Cap: CapRelayCGO}
	if _, err := EncodeSubprotoRequest([]SubprotoCap{cgo, cgo}); err == nil {
		t.Fatal("duplicate must fail")
	}
	if _, err := EncodeSubprotoRequest([]SubprotoCap{{ProtocolID: ProtoRelay, Cap: 4}}); err == nil {
		t.Fatal("Relay=4 is not in the type-3 table")
	}
	if _, err := EncodeSubprotoRequest([]SubprotoCap{{ProtocolID: ProtoFlowCtrl, Cap: 2}}); err == nil {
		t.Fatal("FlowCtrl=2 is negotiated via type 1, not type 3")
	}
}

func TestParseSubprotoRequest(t *testing.T) {
	caps, err := ParseSubprotoRequest([]byte{0x02, 0x06})
	if err != nil || len(caps) != 1 || caps[0] != (SubprotoCap{ProtoRelay, CapRelayCGO}) {
		t.Fatalf("parse [02 06]: %v %#v", err, caps)
	}
	if _, err := ParseSubprotoRequest([]byte{0x02}); err == nil {
		t.Fatal("odd length must fail")
	}
	if _, err := ParseSubprotoRequest(nil); err == nil {
		t.Fatal("empty must fail")
	}
	if _, err := ParseSubprotoRequest([]byte{0x02, 0x05}); err == nil {
		t.Fatal("Relay=5 is the transport, not a requested cap")
	}
	if _, err := ParseSubprotoRequest([]byte{0x02, 0x06, 0x02, 0x06}); err == nil {
		t.Fatal("duplicate must fail")
	}
}

func TestImplementedNegotiableCapsIncludesCGO(t *testing.T) {
	caps := ImplementedNegotiableCaps()
	if len(caps) != 1 || caps[0] != (SubprotoCap{ProtoRelay, CapRelayCGO}) {
		t.Fatalf("CGO 已实现时必须列出 Relay=6: %#v", caps)
	}
}

type fakeProto map[string][]int

func (p fakeProto) Supports(name string, ver int) bool {
	for _, v := range p[name] {
		if v == ver {
			return true
		}
	}
	return false
}

func TestSelectSubprotoRequestRequiresRelay5AndFlowCtrl2(t *testing.T) {
	peer := fakeProto{"Relay": {4, 5, 6}, "FlowCtrl": {1, 2}}
	caps, err := SelectSubprotoRequest(peer)
	if err != nil || len(caps) != 1 || caps[0] != (SubprotoCap{ProtoRelay, CapRelayCGO}) {
		t.Fatalf("对端 Relay=5-6 且 FlowCtrl=2 应请求 CGO: %v %#v", err, caps)
	}

	caps, err = SelectSubprotoRequest(fakeProto{"Relay": {4, 5, 6}, "FlowCtrl": {1}})
	if err != nil || len(caps) != 0 {
		t.Fatalf("无 FlowCtrl=2 不得请求 CGO: %v %#v", err, caps)
	}
	caps, err = SelectSubprotoRequest(fakeProto{"Relay": {4}})
	if err != nil || caps != nil {
		t.Fatalf("无 Relay=5 必须返回空: %v %#v", err, caps)
	}
	caps, err = SelectSubprotoRequest(nil)
	if err != nil || caps != nil {
		t.Fatalf("nil peer: %v %#v", err, caps)
	}
}

func TestEncodeNtorV3ClientMsgCombinesCCAndSubproto(t *testing.T) {
	cm, err := EncodeNtorV3ClientMsg(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cm, EncodeCCRequest()) {
		t.Fatalf("CC only: %x", cm)
	}

	cm, err = EncodeNtorV3ClientMsg(true, []SubprotoCap{{ProtoRelay, CapRelayCGO}})
	if err != nil {
		t.Fatal(err)
	}
	exts, err := ParseNtorV3Extensions(cm)
	if err != nil || len(exts) != 2 {
		t.Fatalf("parse combined: %v %#v", err, exts)
	}
	if exts[0].Type != NtorV3ExtCCRequest || exts[1].Type != NtorV3ExtSubprotoRequest {
		t.Fatalf("extension order: %#v", exts)
	}
	if !bytes.Equal(exts[1].Data, []byte{0x02, 0x06}) {
		t.Fatalf("type 3 body: %x", exts[1].Data)
	}

	if _, err := EncodeNtorV3ClientMsg(false, []SubprotoCap{{ProtoRelay, 4}}); err == nil {
		t.Fatal("unknown cap in client msg must fail")
	}
}

func TestProtocolNameTable(t *testing.T) {
	if ProtocolName(ProtoRelay) != "Relay" || ProtocolName(ProtoFlowCtrl) != "FlowCtrl" {
		t.Fatal("protocol names")
	}
	if ProtocolName(99) != "Proto99" {
		t.Fatal("unknown id")
	}
	c := SubprotoCap{ProtoRelay, CapRelayCGO}
	if c.String() != "Relay=6" {
		t.Fatalf("string: %s", c)
	}
}
