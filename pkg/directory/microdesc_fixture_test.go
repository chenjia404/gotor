package directory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMicrodescFixtureRegression(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../.."))
	docPath := filepath.Join(root, "testdata/microdesc/sample_v3.txt")
	digPath := filepath.Join(root, "testdata/microdesc/sample_v3.digest")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDig, err := os.ReadFile(digPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDigStr := strings.TrimSpace(string(wantDig))
	gotDig := microdescriptorDigest(doc)
	if gotDig != wantDigStr {
		t.Fatalf("digest mismatch\n got %s\nwant %s", gotDig, wantDigStr)
	}

	relay := &Relay{Nickname: "FixtureRelay", MicrodescDigest: gotDig, Flags: []string{"Exit"}}
	client := NewClient(nil)
	if err := client.parseMicrodescriptors(doc, map[string][]*Relay{gotDig: {relay}}); err != nil {
		t.Fatal(err)
	}
	if len(relay.NtorOnionKey) != 32 {
		t.Fatalf("ntor=%d", len(relay.NtorOnionKey))
	}
	if len(relay.IdentityKey) != 32 {
		t.Fatalf("ed25519=%d", len(relay.IdentityKey))
	}
	if len(relay.Family) != 1 || relay.Family[0] != "$DEADBEEF" {
		t.Fatalf("family=%#v", relay.Family)
	}
	if relay.ExitPolicy == nil {
		t.Fatal("exit policy not parsed")
	}
	if relay.IPv6 == "" || relay.IPv6Port != 9001 {
		t.Fatalf("ipv6=%q port=%d", relay.IPv6, relay.IPv6Port)
	}
}
