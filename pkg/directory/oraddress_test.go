package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestParseORAddress(t *testing.T) {
	ip, port, err := ParseORAddress("[2001:db8::1]:9001")
	if err != nil {
		t.Fatal(err)
	}
	if port != 9001 || !ip.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("got %s:%d", ip, port)
	}

	ip, port, err = ParseORAddress("192.0.2.10:443")
	if err != nil {
		t.Fatal(err)
	}
	if port != 443 || ip.To4() == nil {
		t.Fatalf("got %s:%d", ip, port)
	}

	for _, bad := range []string{
		"",
		"not-an-address",
		"[2001:db8::1]",
		"[::]:9001",
		"[::1]:9001",
		"[ff02::1]:9001",
		"[fe80::1]:9001",
		"[2001:db8::1]:0",
		"[2001:db8::1]:65536",
		"example.com:9001",
	} {
		if _, _, err := ParseORAddress(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestParseConsensusIPv6ALine(t *testing.T) {
	consensusData := `network-status-version 3
vote-status consensus
r DualStack AAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBB 2024-01-01 00:00:00 192.0.2.10 9001 0
a [2001:db8::10]:9001
a [2001:db8::11]:443
s Fast Guard Running Stable Valid
pr Relay=1-4 FlowCtrl=1-2
r LegacyDigest CCCCCCCCCCCCCCCCCCCCCC DDDDDDDDDDDDD 2024-01-01 00:00:00 192.0.2.11 9002 0
a sha256=dGVzdGRpZ2VzdA==
s Running Valid
r IPv4Only EEEEEEEEEEEEEEEEEEEEEE FFFFFFFFFFFFF 2024-01-01 00:00:00 192.0.2.12 9003 0
s Running Valid
pr Relay=2
`

	client := NewClient(nil)
	relays, err := client.parseConsensus(strings.NewReader(consensusData))
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 3 {
		t.Fatalf("got %d relays", len(relays))
	}

	dual := relays[0]
	if !dual.HasIPv6ORPort() {
		t.Fatal("dual-stack a line not parsed")
	}
	if dual.IPv6 != "2001:db8::10" || dual.IPv6Port != 9001 {
		t.Fatalf("first IPv6 should win: %s:%d", dual.IPv6, dual.IPv6Port)
	}
	if !dual.AdvertisesExtendIPv6() || !dual.ShouldIncludeExtendIPv6() {
		t.Fatal("Relay=1-4 includes Relay=3")
	}

	legacy := relays[1]
	if legacy.MicrodescDigest != "dGVzdGRpZ2VzdA==" {
		t.Fatalf("legacy sha256 digest: %s", legacy.MicrodescDigest)
	}
	if legacy.HasIPv6ORPort() {
		t.Fatal("sha256= must not be treated as IPv6")
	}

	v4 := relays[2]
	if v4.HasIPv6ORPort() || v4.ShouldIncludeExtendIPv6() {
		t.Fatal("IPv4-only relay must not include [01]")
	}
}

func TestRelayAdvertisesExtendIPv6(t *testing.T) {
	if (*Relay)(nil).AdvertisesExtendIPv6() || (*Relay)(nil).ShouldIncludeExtendIPv6() {
		t.Fatal("nil relay")
	}
	r := &Relay{IPv6: "2001:db8::1", IPv6Port: 9001, Protocols: ParseProtoLine("Relay=4")}
	if r.AdvertisesExtendIPv6() {
		t.Fatal("Relay=4 must not imply Relay=3")
	}
	if r.ShouldIncludeExtendIPv6() {
		t.Fatal("pr 行有 Relay=4 但无 3 时不得发 [01]")
	}
	r.Protocols = ParseProtoLine("Relay=1-4")
	if !r.AdvertisesExtendIPv6() || !r.ShouldIncludeExtendIPv6() {
		t.Fatal("Relay=1-4 should include IPv6 EXTEND")
	}
	r.Protocols = nil
	if !r.ShouldIncludeExtendIPv6() {
		t.Fatal("缺 pr 且有 IPv6 时应附加 [01]")
	}
	r.IPv6 = ""
	if r.ShouldIncludeExtendIPv6() {
		t.Fatal("无 IPv6 不得附加")
	}
}

func TestParseMicrodescriptorIPv6ALine(t *testing.T) {
	ntor := base64.StdEncoding.EncodeToString(bytesRepeat(0x42, 32))
	ed := base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	doc := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIB\n-----END RSA PUBLIC KEY-----\n" +
		"ntor-onion-key " + ntor + "\n" +
		"id ed25519 " + ed + "\n" +
		"a [2001:db8:a::2]:443\n"

	sum := sha256.Sum256([]byte(doc))
	digest := base64.RawStdEncoding.EncodeToString(sum[:])
	relay := &Relay{Nickname: "MD6", MicrodescDigest: digest}
	client := NewClient(nil)
	if err := client.parseMicrodescriptors([]byte(doc), map[string][]*Relay{digest: {relay}}); err != nil {
		t.Fatal(err)
	}
	if relay.IPv6 != "2001:db8:a::2" || relay.IPv6Port != 443 {
		t.Fatalf("microdesc a line: %s:%d", relay.IPv6, relay.IPv6Port)
	}
}
