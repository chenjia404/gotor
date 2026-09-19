package directory

import (
	"strings"
	"testing"
)

func TestDetectConsensusFlavor(t *testing.T) {
	cases := []struct {
		doc    string
		flavor ConsensusFlavor
		ok     bool
	}{
		{"network-status-version 3\nvote-status consensus\n", FlavorNS, true},
		{"network-status-version 3 microdesc\nvote-status consensus\n", FlavorMicrodesc, true},
		{"@type network-status-consensus-3 1.0\nnetwork-status-version 3\n", FlavorNS, true},
		{"not a consensus", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := DetectConsensusFlavor(tc.doc)
		if ok != tc.ok || got != tc.flavor {
			t.Fatalf("doc=%q got (%q,%v) want (%q,%v)", tc.doc, got, ok, tc.flavor, tc.ok)
		}
	}
}

func TestConsensusFlavorFromHTTPPath(t *testing.T) {
	cases := []struct {
		path   string
		flavor ConsensusFlavor
		ok     bool
	}{
		{"/tor/status-vote/current/consensus-microdesc", FlavorMicrodesc, true},
		{"/tor/status-vote/current/consensus-microdesc/", FlavorMicrodesc, true},
		{"/tor/status-vote/current/consensus-microdesc/diff/aaaa/all", FlavorMicrodesc, true},
		{"/tor/status-vote/current/consensus", FlavorNS, true},
		{"/tor/status-vote/current/consensus/", FlavorNS, true},
		{"/tor/status-vote/current/consensus/diff/bbbb/all", FlavorNS, true},
		{"/tor/micro/all", "", false},
	}
	for _, tc := range cases {
		got, ok := ConsensusFlavorFromHTTPPath(tc.path)
		if ok != tc.ok || got != tc.flavor {
			t.Fatalf("path=%q got (%q,%v) want (%q,%v)", tc.path, got, ok, tc.flavor, tc.ok)
		}
	}
}

func TestNSConsensusURL(t *testing.T) {
	in := "http://128.31.0.39:9231/tor/status-vote/current/consensus-microdesc"
	want := "http://128.31.0.39:9231/tor/status-vote/current/consensus"
	if got := NSConsensusURL(in); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := NSConsensusURL(want); got != want {
		t.Fatalf("already-ns URL: got %q", got)
	}
}

func TestLookupHistoricalConsensusFlavorDoesNotCross(t *testing.T) {
	dir := t.TempDir()
	ns := "" +
		"network-status-version 3\n" +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"valid-after 2024-01-01 00:00:00\n" +
		"fresh-until 2024-01-01 01:00:00\n" +
		"valid-until 2024-01-01 03:00:00\n" +
		"directory-footer\n" +
		"directory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nNS\n-----END SIGNATURE-----\n"
	digest := strings.ToLower(consensusDiffFromDigest(ns))
	if err := writeCachedConsensusFile(dir, consensusPrevFile(FlavorNS), []byte(ns)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := LookupHistoricalConsensus(dir, []string{digest}, ""); ok {
		t.Fatal("microdesc 查找不得命中 ns .prev")
	}
	got, d, ok := LookupHistoricalConsensusFlavor(dir, FlavorNS, []string{digest}, "")
	if !ok || got != ns || d != digest {
		t.Fatalf("ns 查找应命中本库: ok=%v digest=%s", ok, d)
	}
}
