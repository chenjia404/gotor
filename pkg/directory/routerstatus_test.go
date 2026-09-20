package directory

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestFormatRouterStatus(t *testing.T) {
	id := make([]byte, 20)
	for i := range id {
		id[i] = 0xAB
	}
	r := &Relay{
		Nickname:        "TestRelay",
		Fingerprint:     base64.RawStdEncoding.EncodeToString(id),
		RSAIdentity:     id,
		FingerprintHex:  "ABABABABABABABABABABABABABABABABABABABAB",
		Address:         "192.0.2.1",
		ORPort:          9001,
		DirPort:         0,
		Flags:           []string{"Fast", "Running", "Valid"},
		Published:       time.Date(2038, 1, 1, 0, 0, 0, 0, time.UTC),
		MicrodescDigest: "jauY803ygX19rw14B2x4suqNIIMIPPbtYBAwA9UegdI",
		Bandwidth:       42,
		IPv6:            "2001:db8::1",
		IPv6Port:        9001,
		ExitPolicy:      mustPolicy(t, "p accept 80,443"),
	}
	got := FormatRouterStatus(r)
	if !strings.Contains(got, "r TestRelay ") {
		t.Fatalf("r line: %s", got)
	}
	if !strings.Contains(got, "2038-01-01 00:00:00") {
		t.Fatalf("published: %s", got)
	}
	if !strings.Contains(got, "m jauY803ygX19rw14B2x4suqNIIMIPPbtYBAwA9UegdI") {
		t.Fatalf("m line: %s", got)
	}
	if !strings.Contains(got, "a [2001:db8::1]:9001") {
		t.Fatalf("a line: %s", got)
	}
	if !strings.Contains(got, "s Fast Running Valid") {
		t.Fatalf("s line: %s", got)
	}
	if !strings.Contains(got, "w Bandwidth=42") {
		t.Fatalf("w line: %s", got)
	}
	if !strings.Contains(got, "p accept 80,443") {
		t.Fatalf("p line: %s", got)
	}
	if !MatchRelayIdentity(r, "$ABABABABABABABABABABABABABABABABABABABAB") {
		t.Fatal("hex identity")
	}
	if FindRelayByID([]*Relay{r}, r.Fingerprint) != r {
		t.Fatal("base64 identity")
	}
}

func mustPolicy(t *testing.T, line string) *ExitPolicySummary {
	t.Helper()
	p, err := ParseExitPolicySummary(line)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseConsensusStoresPublished(t *testing.T) {
	consensusData := `network-status-version 3
vote-status consensus
consensus-method 33
r TestRelay AAAAAAAAAAAAAAAAAAAAAA 2038-01-01 00:00:00 192.168.1.1 9001 0
m jauY803ygX19rw14B2x4suqNIIMIPPbtYBAwA9UegdI
s Fast Guard Running Stable Valid
`
	client := NewClient(nil)
	relays, err := client.parseConsensus(strings.NewReader(consensusData))
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 {
		t.Fatalf("relays %d", len(relays))
	}
	if relays[0].Published.UTC() != time.Date(2038, 1, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("published %v", relays[0].Published)
	}
	body := FormatRouterStatus(relays[0])
	if !strings.Contains(body, "r TestRelay AAAAAAAAAAAAAAAAAAAAAA 2038-01-01 00:00:00 192.168.1.1 9001 0") {
		t.Fatalf("%s", body)
	}
}
