package directory

import "testing"

func TestParseProtoLine(t *testing.T) {
	p := ParseProtoLine("pr Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=5 HSRend=2 Link=5 LinkAuth=3 Microdesc=2 Relay=4 Padding=2 FlowCtrl=1-2 Conflux=2")
	if !p.Supports("Relay", 4) {
		t.Fatal("Relay=4 should be supported")
	}
	if p.Supports("Relay", 5) {
		t.Fatal("Relay=5 should not be supported")
	}
	if !p.Supports("FlowCtrl", 1) || !p.Supports("FlowCtrl", 2) {
		t.Fatal("FlowCtrl=1-2 should include 1 and 2")
	}
	if !p.Supports("LinkAuth", 3) {
		t.Fatal("LinkAuth=3 should be supported")
	}
}

func TestParseProtoLineCommaList(t *testing.T) {
	p := ParseProtoLine("LinkAuth=1,3")
	if !p.Supports("LinkAuth", 1) || !p.Supports("LinkAuth", 3) || p.Supports("LinkAuth", 2) {
		t.Fatalf("comma list: %#v", p)
	}
}

func TestRelayUseNtorV3(t *testing.T) {
	r := &Relay{
		RSAIdentity:  bytesRepeat(0x01, 20),
		NtorOnionKey: bytesRepeat(0x02, 32),
		IdentityKey:  bytesRepeat(0x03, 32),
	}
	if !r.UseNtorV3() {
		t.Fatal("missing pr should still use ntor-v3 when Ed25519 keys exist")
	}
	r.Protocols = ParseProtoLine("Relay=3 FlowCtrl=1")
	if r.UseNtorV3() {
		t.Fatal("Relay=3 must not use ntor-v3")
	}
	r.Protocols = ParseProtoLine("Relay=4 FlowCtrl=1-2")
	if !r.UseNtorV3() || !r.RequestCongestionControl() {
		t.Fatal("Relay=4 FlowCtrl=2 should request ntor-v3 + CC")
	}
	r.IdentityKey = nil
	if r.UseNtorV3() {
		t.Fatal("missing Ed25519 must not use ntor-v3")
	}
}
