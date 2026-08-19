package path

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func confluxRelay(nick, fp, addr string, flags []string) *directory.Relay {
	return &directory.Relay{
		Nickname:    nick,
		Fingerprint: fp,
		Address:     addr,
		ORPort:      9001,
		Flags:       flags,
		Bandwidth:   1000,
		Protocols:   directory.ParseProtoLine("Relay=4 FlowCtrl=1-2 Conflux=2"),
	}
}

func newConfluxSelector(relays []*directory.Relay, guards []*directory.Relay) *Selector {
	s := NewSelector(directory.NewClient(logger.NewDefault()), logger.NewDefault())
	s.relays = relays
	s.guards = guards
	return s
}

func TestPathAdvertisesConflux(t *testing.T) {
	g := confluxRelay("G1", "AA11", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	m := confluxRelay("M1", "BB11", "172.16.2.1", []string{"Running", "Valid"})
	e := confluxRelay("E1", "CC11", "192.168.3.1", []string{"Running", "Valid", "Exit"})
	if !PathAdvertisesConflux(&Path{Guard: g, Middle: m, Exit: e}) {
		t.Fatal("all hops Conflux=2 + FlowCtrl=2")
	}
	e.Protocols = directory.ParseProtoLine("Relay=4 FlowCtrl=1-2")
	if PathAdvertisesConflux(&Path{Guard: g, Middle: m, Exit: e}) {
		t.Fatal("exit without Conflux must not advertise")
	}
	if PathAdvertisesConflux(nil) {
		t.Fatal("nil path")
	}
}

func TestSelectConfluxPath(t *testing.T) {
	g1 := confluxRelay("G1", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	m1 := confluxRelay("M1", "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111", "172.16.2.1", []string{"Running", "Valid"})
	e1 := confluxRelay("E1", "CCCC1111CCCC1111CCCC1111CCCC1111CCCC1111", "192.168.3.1", []string{"Running", "Valid", "Exit"})
	sel := newConfluxSelector([]*directory.Relay{g1, m1, e1}, []*directory.Relay{g1})
	p, err := sel.SelectConfluxPath(443)
	if err != nil {
		t.Fatal(err)
	}
	if !PathAdvertisesConflux(p) {
		t.Fatal("first path must advertise Conflux")
	}
	plain := newConfluxSelector([]*directory.Relay{
		{Nickname: "G", Fingerprint: "AA", Address: "10.0.1.1", Flags: []string{"Running", "Valid", "Guard", "Stable"}, Protocols: directory.ParseProtoLine("Relay=4 FlowCtrl=1-2")},
	}, nil)
	if _, err := plain.SelectConfluxPath(443); err == nil {
		t.Fatal("no Conflux guards must fail")
	}
}

func TestSelectConfluxSecondPath(t *testing.T) {
	g1 := confluxRelay("G1", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	g2 := confluxRelay("G2", "AAAA2222AAAA2222AAAA2222AAAA2222AAAA2222", "10.1.1.2", []string{"Running", "Valid", "Guard", "Stable"})
	m1 := confluxRelay("M1", "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111", "172.16.2.1", []string{"Running", "Valid"})
	m2 := confluxRelay("M2", "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222", "172.17.2.2", []string{"Running", "Valid"})
	e1 := confluxRelay("E1", "CCCC1111CCCC1111CCCC1111CCCC1111CCCC1111", "192.168.3.1", []string{"Running", "Valid", "Exit"})
	plain := &directory.Relay{
		Nickname:    "Plain",
		Fingerprint: "DDDD1111DDDD1111DDDD1111DDDD1111DDDD1111",
		Address:     "192.170.4.1",
		ORPort:      9001,
		Flags:       []string{"Running", "Valid", "Guard", "Stable"},
		Bandwidth:   1000,
		Protocols:   directory.ParseProtoLine("Relay=4 FlowCtrl=1-2"),
	}

	sel := newConfluxSelector([]*directory.Relay{g1, g2, m1, m2, e1, plain}, []*directory.Relay{g1, g2, plain})
	first := &Path{Guard: g1, Middle: m1, Exit: e1}
	second, err := sel.SelectConfluxSecondPath(first)
	if err != nil {
		t.Fatal(err)
	}
	if second.Exit != e1 {
		t.Fatal("second leg must reuse the same exit")
	}
	if sameRelayIdentity(second.Guard, first.Guard) || sameRelayIdentity(second.Middle, first.Middle) {
		t.Fatal("second leg must use different guard and middle")
	}
	if !PathAdvertisesConflux(second) {
		t.Fatal("second path must advertise Conflux")
	}
	if second.Guard.Nickname == "Plain" {
		t.Fatal("must not pick a hop that only has FlowCtrl")
	}
}

func TestSelectConfluxSecondPathExcludesFamilyAndSubnet(t *testing.T) {
	g1 := confluxRelay("G1", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	gSameNet := confluxRelay("Gnet", "AAAA3333AAAA3333AAAA3333AAAA3333AAAA3333", "10.0.9.9", []string{"Running", "Valid", "Guard", "Stable"})
	g2 := confluxRelay("G2", "AAAA2222AAAA2222AAAA2222AAAA2222AAAA2222", "10.1.1.2", []string{"Running", "Valid", "Guard", "Stable"})
	m1 := confluxRelay("M1", "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111", "172.16.2.1", []string{"Running", "Valid"})
	mSameNet := confluxRelay("Mnet", "BBBB3333BBBB3333BBBB3333BBBB3333BBBB3333", "172.16.9.9", []string{"Running", "Valid"})
	m2 := confluxRelay("M2", "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222", "172.17.2.2", []string{"Running", "Valid"})
	e1 := confluxRelay("E1", "CCCC1111CCCC1111CCCC1111CCCC1111CCCC1111", "192.168.3.1", []string{"Running", "Valid", "Exit"})
	sel := newConfluxSelector([]*directory.Relay{g1, gSameNet, g2, m1, mSameNet, m2, e1}, []*directory.Relay{g1, gSameNet, g2})
	second, err := sel.SelectConfluxSecondPath(&Path{Guard: g1, Middle: m1, Exit: e1})
	if err != nil {
		t.Fatal(err)
	}
	if second.Guard == gSameNet || second.Middle == mSameNet {
		t.Fatal("second leg must not share /16 with first guard/middle")
	}
	if second.Guard != g2 || second.Middle != m2 {
		t.Fatalf("want G2/M2, got %s/%s", second.Guard.Nickname, second.Middle.Nickname)
	}
}

func TestSelectConfluxSecondPathExcludesFamily(t *testing.T) {
	g1 := confluxRelay("G1", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	gFam := confluxRelay("Gfam", "AAAA3333AAAA3333AAAA3333AAAA3333AAAA3333", "11.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	g2 := confluxRelay("G2", "AAAA2222AAAA2222AAAA2222AAAA2222AAAA2222", "10.1.1.2", []string{"Running", "Valid", "Guard", "Stable"})
	g1.Family = []string{gFam.Fingerprint}
	gFam.Family = []string{g1.Fingerprint}
	m1 := confluxRelay("M1", "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111", "172.16.2.1", []string{"Running", "Valid"})
	m2 := confluxRelay("M2", "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222", "172.17.2.2", []string{"Running", "Valid"})
	e1 := confluxRelay("E1", "CCCC1111CCCC1111CCCC1111CCCC1111CCCC1111", "192.168.3.1", []string{"Running", "Valid", "Exit"})
	sel := newConfluxSelector([]*directory.Relay{g1, gFam, g2, m1, m2, e1}, []*directory.Relay{g1, gFam, g2})
	second, err := sel.SelectConfluxSecondPath(&Path{Guard: g1, Middle: m1, Exit: e1})
	if err != nil {
		t.Fatal(err)
	}
	if second.Guard == gFam {
		t.Fatal("second guard must not share family with first guard")
	}
	if second.Guard != g2 {
		t.Fatalf("want G2, got %s", second.Guard.Nickname)
	}
}

func TestSelectConfluxSecondPathRequiresDistinctGuard(t *testing.T) {
	g1 := confluxRelay("G1", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	m1 := confluxRelay("M1", "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111", "172.16.2.1", []string{"Running", "Valid"})
	m2 := confluxRelay("M2", "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222", "172.17.2.2", []string{"Running", "Valid"})
	e1 := confluxRelay("E1", "CCCC1111CCCC1111CCCC1111CCCC1111CCCC1111", "192.168.3.1", []string{"Running", "Valid", "Exit"})
	sel := newConfluxSelector([]*directory.Relay{g1, m1, m2, e1}, []*directory.Relay{g1})
	_, err := sel.SelectConfluxSecondPath(&Path{Guard: g1, Middle: m1, Exit: e1})
	if err == nil {
		t.Fatal("only one Conflux guard must not produce a second path")
	}
}

func TestSelectConfluxSecondPathRejectsNonConfluxFirst(t *testing.T) {
	g1 := confluxRelay("G1", "AA11", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	m1 := confluxRelay("M1", "BB11", "172.16.2.1", []string{"Running", "Valid"})
	e1 := &directory.Relay{
		Nickname:    "E1",
		Fingerprint: "CC11",
		Address:     "192.168.3.1",
		Protocols:   directory.ParseProtoLine("Relay=4 FlowCtrl=1-2"),
	}
	sel := newConfluxSelector([]*directory.Relay{g1, m1, e1}, []*directory.Relay{g1})
	_, err := sel.SelectConfluxSecondPath(&Path{Guard: g1, Middle: m1, Exit: e1})
	if err == nil {
		t.Fatal("first path without Conflux exit must fail")
	}
}
