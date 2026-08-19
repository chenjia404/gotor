package directory

import (
	"encoding/base64"
	"testing"
)

func TestParseSharedRandValueLine(t *testing.T) {
	v := make([]byte, 32)
	v[0] = 7
	b64 := base64.StdEncoding.EncodeToString(v)
	line := "shared-rand-current-value 8 " + b64
	got := parseSharedRandValueLine(line)
	if len(got) != 32 || got[0] != 7 {
		t.Fatalf("%x", got)
	}
}
