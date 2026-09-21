package onion

import "testing"

func TestParseFlowControlLine(t *testing.T) {
	p := parseFlowControlLine("1-2 31")
	if p == nil || !p.SupportsFlowCtrl2() || p.SendmeInc != 31 {
		t.Fatalf("got %+v", p)
	}
	if parseFlowControlLine("1-1 31") != nil && parseFlowControlLine("1-1 31").SupportsFlowCtrl2() {
		t.Fatal("1-1 must not claim FlowCtrl=2")
	}
	if parseFlowControlLine("bad") != nil {
		t.Fatal("expected nil")
	}
}

func TestSendmeIncCompatible(t *testing.T) {
	if !sendmeIncCompatible(31, 31) || !sendmeIncCompatible(31, 50) || !sendmeIncCompatible(50, 31) {
		t.Fatal("within 2x should pass")
	}
	if sendmeIncCompatible(31, 100) {
		t.Fatal("31 vs 100 should fail")
	}
}

func TestValidateFlowControlForRequest(t *testing.T) {
	fc := &FlowControlParams{VersionMin: 1, VersionMax: 2, SendmeInc: 31}
	if err := validateFlowControlForRequest(fc, 2, 31); err != nil {
		t.Fatal(err)
	}
	if err := validateFlowControlForRequest(fc, 0, 31); err == nil {
		t.Fatal("cc_alg=0 must reject")
	}
}

func TestEncodeCCRequestExtension(t *testing.T) {
	ext := encodeCCRequestExtension()
	if len(ext) != 2 || ext[0] != introExtCCRequest || ext[1] != 0 {
		t.Fatalf("%v", ext)
	}
}
