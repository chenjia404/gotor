package circuit

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

var _ relayExtendIPv6 = (*directory.Relay)(nil)

func TestBuildExtend2DataIPv4OnlyNSPEC3(t *testing.T) {
	ext := NewExtension(NewCircuit(1), logger.NewDefault())
	ext.SetTargetRelay(newStubRelay())
	data, err := ext.buildExtend2Data("192.0.2.1:9001", HandshakeTypeNTor, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 3 {
		t.Fatalf("IPv4-only NSPEC=%d, want 3", data[0])
	}
	if strings.Contains(DescribeExtend2(data), "[01]") {
		t.Fatalf("IPv4-only must not emit [01]: %s", DescribeExtend2(data))
	}
}

func TestBuildExtend2DataDualStackNSPEC4(t *testing.T) {
	ext := NewExtension(NewCircuit(1), logger.NewDefault())
	relay := newStubRelay()
	relay.ipv6 = net.ParseIP("2001:db8::10")
	relay.ipv6Port = 9001
	ext.SetTargetRelay(relay)

	hs := make([]byte, 32)
	data, err := ext.buildExtend2Data("192.0.2.10:9001", HandshakeTypeNTor, hs)
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 4 {
		t.Fatalf("dual-stack NSPEC=%d, want 4", data[0])
	}

	types, bodies := parseExtend2Specs(t, data)
	if types[0] != 0 || types[1] != 2 || types[2] != 3 || types[3] != 1 {
		t.Fatalf("specifier order %v, want [00 02 03 01]", types)
	}
	if len(bodies[3]) != 18 {
		t.Fatalf("[01] LSLEN=%d, want 18", len(bodies[3]))
	}
	wantIP := net.ParseIP("2001:db8::10").To16()
	if !net.IP(bodies[3][:16]).Equal(wantIP) {
		t.Fatalf("[01] IP = %s", net.IP(bodies[3][:16]))
	}
	if binary.BigEndian.Uint16(bodies[3][16:18]) != 9001 {
		t.Fatalf("[01] port = %d", binary.BigEndian.Uint16(bodies[3][16:18]))
	}

	dump := DescribeExtend2(data)
	if !strings.Contains(dump, "[01] [2001:db8::10]:9001") {
		t.Fatalf("dump missing IPv6: %s", dump)
	}
}

func TestBuildExtend2DataRelayBelow3OmitsIPv6(t *testing.T) {
	ext := NewExtension(NewCircuit(1), logger.NewDefault())
	relay := newStubRelay()
	relay.ipv6 = net.ParseIP("2001:db8::10")
	relay.ipv6Port = 9001
	relay.noIPv6Spec = true
	ext.SetTargetRelay(relay)

	data, err := ext.buildExtend2Data("192.0.2.10:9001", HandshakeTypeNTor, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 3 {
		t.Fatalf("Relay<3 NSPEC=%d, want 3", data[0])
	}
}

func TestBuildExtend2DataIPv6OnlyTargetNoDuplicate(t *testing.T) {
	ext := NewExtension(NewCircuit(1), logger.NewDefault())
	relay := newStubRelay()
	relay.ipv6 = net.ParseIP("2001:db8::aa")
	relay.ipv6Port = 443
	ext.SetTargetRelay(relay)

	data, err := ext.buildExtend2Data("[2001:db8::1]:9001", HandshakeTypeNTor, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 3 {
		t.Fatalf("IPv6-only target NSPEC=%d, want 3（不重复 [01]）", data[0])
	}
	types, _ := parseExtend2Specs(t, data)
	if types[0] != 1 || types[1] != 2 || types[2] != 3 {
		t.Fatalf("order %v, want [01 02 03]", types)
	}
}

func TestEncodeExtend2DataExported(t *testing.T) {
	relay := newStubRelay()
	relay.ipv6 = net.ParseIP("2001:db8::2")
	relay.ipv6Port = 443
	data, err := EncodeExtend2Data("198.51.100.2:443", relay, HandshakeTypeNTor, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 4 {
		t.Fatalf("NSPEC=%d", data[0])
	}
}

func parseExtend2Specs(t *testing.T, data []byte) ([]byte, [][]byte) {
	t.Helper()
	if len(data) < 1 {
		t.Fatal("empty")
	}
	nspec := int(data[0])
	types := make([]byte, 0, nspec)
	bodies := make([][]byte, 0, nspec)
	off := 1
	for i := 0; i < nspec; i++ {
		if off+2 > len(data) {
			t.Fatal("truncated specifier header")
		}
		lstype := data[off]
		lslen := int(data[off+1])
		off += 2
		if off+lslen > len(data) {
			t.Fatal("truncated specifier body")
		}
		types = append(types, lstype)
		bodies = append(bodies, append([]byte(nil), data[off:off+lslen]...))
		off += lslen
	}
	return types, bodies
}
