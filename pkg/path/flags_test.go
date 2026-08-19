package path

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestSelectMiddleRejectsNonFast(t *testing.T) {
	guard := &directory.Relay{
		Fingerprint: "G1",
		Nickname:    "g",
		Address:     "198.51.100.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
	}
	slow := &directory.Relay{
		Fingerprint: "Mslow",
		Nickname:    "slow",
		Address:     "203.0.113.1",
		Flags:       []string{"Running", "Valid"},
	}
	fast := &directory.Relay{
		Fingerprint: "Mfast",
		Nickname:    "fast",
		Address:     "192.0.2.1",
		Flags:       []string{"Running", "Valid", "Fast"},
	}
	exit := &directory.Relay{
		Fingerprint: "E1",
		Nickname:    "e",
		Address:     "172.16.0.8",
		Flags:       []string{"Exit", "Running", "Valid", "Fast"},
	}

	s := NewSelector(directory.NewClient(nil), nil)
	s.relays = []*directory.Relay{guard, slow, fast, exit}

	got, err := s.selectMiddle(guard, exit)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "Mfast" {
		t.Fatalf("middle = %s, 非 Fast 不得入选", got.Fingerprint)
	}
}

func TestSelectExitRejectsNonFast(t *testing.T) {
	guard := &directory.Relay{
		Fingerprint: "G1",
		Address:     "198.51.100.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
	}
	slow := &directory.Relay{
		Fingerprint: "Eslow",
		Nickname:    "slow",
		Address:     "203.0.113.8",
		Flags:       []string{"Exit", "Running", "Valid"},
	}
	ok := &directory.Relay{
		Fingerprint: "Eok",
		Nickname:    "ok",
		Address:     "192.0.2.8",
		Flags:       []string{"Exit", "Running", "Valid", "Fast"},
	}
	s := NewSelector(directory.NewClient(nil), nil)
	s.relays = []*directory.Relay{guard, slow, ok}
	got, err := s.selectExit(443, guard)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "Eok" {
		t.Fatalf("exit = %s, 非 Fast 不得入选", got.Fingerprint)
	}
}

func TestSelectExitRejectsMiddleOnlyAndBadExit(t *testing.T) {
	guard := &directory.Relay{
		Fingerprint: "G1",
		Address:     "198.51.100.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
	}
	middleOnly := &directory.Relay{
		Fingerprint: "Emo",
		Nickname:    "mo",
		Address:     "203.0.113.8",
		Flags:       []string{"Exit", "Running", "Valid", "Fast", "MiddleOnly"},
	}
	badExit := &directory.Relay{
		Fingerprint: "Ebad",
		Nickname:    "bad",
		Address:     "203.0.113.9",
		Flags:       []string{"Exit", "Running", "Valid", "Fast", "BadExit"},
	}
	ok := &directory.Relay{
		Fingerprint: "Eok",
		Nickname:    "ok",
		Address:     "192.0.2.8",
		Flags:       []string{"Exit", "Running", "Valid", "Fast"},
	}

	s := NewSelector(directory.NewClient(nil), nil)
	s.relays = []*directory.Relay{guard, middleOnly, badExit, ok}

	got, err := s.selectExit(443, guard)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "Eok" {
		t.Fatalf("exit = %s, MiddleOnly/BadExit 不得入选", got.Fingerprint)
	}
}

func TestSelectGuardRejectsMiddleOnlyAndNonFast(t *testing.T) {
	slow := &directory.Relay{
		Fingerprint: "Gslow",
		Nickname:    "slow",
		Address:     "198.51.100.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable"},
	}
	middleOnly := &directory.Relay{
		Fingerprint: "Gmo",
		Nickname:    "mo",
		Address:     "203.0.113.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast", "MiddleOnly"},
	}
	ok := &directory.Relay{
		Fingerprint: "Gok",
		Nickname:    "ok",
		Address:     "192.0.2.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
	}

	s := NewSelector(directory.NewClient(nil), nil)
	s.guards = []*directory.Relay{slow, middleOnly, ok}

	got, err := s.selectGuard()
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "Gok" {
		t.Fatalf("guard = %s, 非 Fast / MiddleOnly 不得入选", got.Fingerprint)
	}
}

func TestSelectGuardFailsWhenNoneUsable(t *testing.T) {
	s := NewSelector(directory.NewClient(nil), nil)
	s.guards = []*directory.Relay{{
		Fingerprint: "G1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable"},
	}}
	if _, err := s.selectGuard(); err == nil {
		t.Fatal("没有 Fast Guard 必须失败")
	}
}

func TestSelectMiddleAllowsMiddleOnly(t *testing.T) {
	guard := &directory.Relay{
		Fingerprint: "G1",
		Address:     "198.51.100.1",
		Flags:       []string{"Guard", "Running", "Valid", "Stable", "Fast"},
	}
	mid := &directory.Relay{
		Fingerprint: "M1",
		Nickname:    "mo",
		Address:     "203.0.113.1",
		Flags:       []string{"Running", "Valid", "Fast", "MiddleOnly"},
	}
	exit := &directory.Relay{
		Fingerprint: "E1",
		Address:     "172.16.0.8",
		Flags:       []string{"Exit", "Running", "Valid", "Fast"},
	}
	s := NewSelector(directory.NewClient(nil), nil)
	s.relays = []*directory.Relay{guard, mid, exit}
	got, err := s.selectMiddle(guard, exit)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "M1" {
		t.Fatalf("MiddleOnly 应可作 middle, got %s", got.Fingerprint)
	}
}

func TestPathHopsMeetFlagConstraints(t *testing.T) {
	ok := &Path{
		Guard:  &directory.Relay{Flags: []string{"Guard", "Running", "Valid", "Stable", "Fast"}},
		Middle: &directory.Relay{Flags: []string{"Running", "Valid", "Fast"}},
		Exit:   &directory.Relay{Flags: []string{"Exit", "Running", "Valid", "Fast"}},
	}
	if !ok.hopsMeetFlagConstraints() {
		t.Fatal("合格三跳必须通过")
	}
	ok.Exit.Flags = append(ok.Exit.Flags, "MiddleOnly")
	if ok.hopsMeetFlagConstraints() {
		t.Fatal("MiddleOnly Exit 必须失败")
	}
}

func TestSelectConfluxRejectsNonFastGuard(t *testing.T) {
	gSlow := confluxRelay("Gslow", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "10.0.1.1", []string{"Running", "Valid", "Guard", "Stable"})
	gSlow.Flags = []string{"Running", "Valid", "Guard", "Stable"} // 去掉 helper 加的 Fast
	gOK := confluxRelay("Gok", "AAAA2222AAAA2222AAAA2222AAAA2222AAAA2222", "10.1.1.2", []string{"Running", "Valid", "Guard", "Stable", "Fast"})
	m1 := confluxRelay("M1", "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111", "172.16.2.1", []string{"Running", "Valid", "Fast"})
	e1 := confluxRelay("E1", "CCCC1111CCCC1111CCCC1111CCCC1111CCCC1111", "192.168.3.1", []string{"Running", "Valid", "Exit", "Fast"})
	sel := newConfluxSelector([]*directory.Relay{gSlow, gOK, m1, e1}, []*directory.Relay{gSlow, gOK})
	p, err := sel.SelectConfluxPath(443)
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Nickname != "Gok" {
		t.Fatalf("Conflux Guard = %s, 非 Fast 不得入选", p.Guard.Nickname)
	}
}
