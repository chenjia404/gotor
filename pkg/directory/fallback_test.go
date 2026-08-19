package directory

import "testing"

func TestFallbackDirURL(t *testing.T) {
	u := fallbackDirURL("192.0.2.1:9030 orport=9001 id=AAAA")
	if u != "http://192.0.2.1:9030/tor/status-vote/current/consensus-microdesc" {
		t.Fatalf("%s", u)
	}
	c := NewClient(nil)
	c.ApplyFallbackDirs([]string{"192.0.2.1:9030"}, false)
	if len(c.authorities) != 1 {
		t.Fatalf("authorities %d", len(c.authorities))
	}
}
