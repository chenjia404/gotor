package onion

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/path"
)

func TestSelectOnionPathUsesFixedL2(t *testing.T) {
	pool := []*directory.Relay{
		{Nickname: "G1", Fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Flags: []string{"Running", "Valid", "Guard", "Fast", "Stable"}},
		{Nickname: "G2", Fingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Flags: []string{"Running", "Valid", "Guard", "Fast", "Stable"}},
		{Nickname: "G3", Fingerprint: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", Flags: []string{"Running", "Valid", "Guard", "Fast", "Stable"}},
		{Nickname: "G4", Fingerprint: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", Flags: []string{"Running", "Valid", "Guard", "Fast", "Stable"}},
		{Nickname: "G5", Fingerprint: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", Flags: []string{"Running", "Valid", "Guard", "Fast", "Stable"}},
		{Nickname: "T", Fingerprint: "1111111111111111111111111111111111111111", Flags: []string{"Running", "Valid", "Guard", "Fast", "Stable"}},
	}
	v := path.NewVanguardSet(path.VanguardConfig{Count: 4}, nil)
	p1, err := selectOnionPath(v, nil, pool, pool[5])
	if err != nil {
		t.Fatal(err)
	}
	fixed := v.Fingerprints()
	if len(fixed) != 4 {
		t.Fatalf("L2 %v", fixed)
	}
	p2, err := selectOnionPath(v, nil, pool, pool[5])
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, fp := range fixed {
		if p2.Middle.Fingerprint == fp {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("第二次 L2 %s 不在固定集合 %v", p2.Middle.Fingerprint, fixed)
	}
	if p1.Exit != pool[5] || p2.Exit != pool[5] {
		t.Fatal("末跳必须是目标")
	}
}
