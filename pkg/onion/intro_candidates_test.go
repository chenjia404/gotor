package onion

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestShuffleHSDirectoriesPreservesSet(t *testing.T) {
	in := []*HSDirectory{
		{Fingerprint: "a"},
		{Fingerprint: "b"},
		{Fingerprint: "c"},
		{Fingerprint: "d"},
		{Fingerprint: "e"},
	}
	out := shuffleHSDirectories(in)
	if len(out) != len(in) {
		t.Fatalf("len %d want %d", len(out), len(in))
	}
	if &out[0] == &in[0] {
		t.Fatal("shuffle must copy the slice")
	}
	seen := map[string]int{}
	for _, h := range out {
		seen[h.Fingerprint]++
	}
	for _, h := range in {
		if seen[h.Fingerprint] != 1 {
			t.Fatalf("fingerprint %s count %d", h.Fingerprint, seen[h.Fingerprint])
		}
	}
}

func TestIntroPointCandidatesRequireFastStable(t *testing.T) {
	relays := []*directory.Relay{
		{
			Fingerprint:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			FingerprintHex: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Flags:          []string{"Running", "Valid", "Fast", "Stable"},
		},
		{
			Fingerprint:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			FingerprintHex: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			Flags:          []string{"Running", "Valid", "HSDir"},
		},
	}
	got := IntroPointCandidatesFromRelays(relays)
	if len(got) != 1 || got[0].Fingerprint != relays[0].Fingerprint {
		t.Fatalf("got %+v", got)
	}
}
