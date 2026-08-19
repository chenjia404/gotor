package onion

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestHSDirectoriesFromRelays(t *testing.T) {
	relays := []*directory.Relay{
		{Nickname: "a", Address: "1.1.1.1", ORPort: 9001, DirPort: 9030, Flags: []string{"Running", "Valid", "HSDir"}, Fingerprint: "aa"},
		{Nickname: "b", Address: "2.2.2.2", ORPort: 9001, DirPort: 0, Flags: []string{"Running", "Valid", "HSDir"}, Fingerprint: "bb"},
		{Nickname: "c", Address: "3.3.3.3", ORPort: 9001, DirPort: 80, Flags: []string{"Running", "Valid", "V2Dir"}, Fingerprint: "cc"},
		nil,
	}
	got := HSDirectoriesFromRelays(relays)
	// a + b (HSDir) + c (DirPort V2Dir)
	if len(got) != 3 {
		t.Fatalf("got %d want 3", len(got))
	}
	var orOnly, withDir int
	for _, h := range got {
		if h.DirPort == 0 {
			orOnly++
			if h.Relay == nil {
				t.Fatal("HSDir without DirPort must keep Relay for BEGIN_DIR")
			}
		} else {
			withDir++
		}
	}
	if orOnly != 1 || withDir != 2 {
		t.Fatalf("orOnly=%d withDir=%d", orOnly, withDir)
	}
}
