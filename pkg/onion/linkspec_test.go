package onion

import (
	"encoding/binary"
	"testing"
)

func TestParseLinkSpecifierList(t *testing.T) {
	// nspec=2: IPv4 + Ed25519
	buf := []byte{2}
	buf = append(buf, LSTypeIPv4, 6)
	buf = append(buf, 1, 2, 3, 4)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 9001)
	buf = append(buf, port...)
	buf = append(buf, LSTypeEd25519ID, 32)
	ed := make([]byte, 32)
	ed[0] = 0xab
	buf = append(buf, ed...)

	r, err := ParseLinkSpecifierList(buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.IPv4.String() != "1.2.3.4" || r.IPv4Port != 9001 {
		t.Fatalf("%v %d", r.IPv4, r.IPv4Port)
	}
	if len(r.Ed25519ID) != 32 || r.Ed25519ID[0] != 0xab {
		t.Fatal(r.Ed25519ID)
	}
}
