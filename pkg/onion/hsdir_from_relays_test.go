package onion

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestHSDirectoriesFromRelays(t *testing.T) {
	relays := []*directory.Relay{
		{Nickname: "a", Address: "1.1.1.1", ORPort: 9001, DirPort: 9030, Flags: []string{"Running", "Valid", "HSDir"}},
		{Nickname: "b", Address: "2.2.2.2", ORPort: 9001, DirPort: 0, Flags: []string{"Running", "Valid", "HSDir"}},
		{Nickname: "c", Address: "3.3.3.3", ORPort: 9001, DirPort: 80, Flags: []string{"Running", "Valid", "V2Dir"}},
		nil,
	}
	got := HSDirectoriesFromRelays(relays)
	if len(got) != 2 {
		t.Fatalf("got %d want 2 (a HSDir+DirPort, c V2Dir+DirPort)", len(got))
	}
}
