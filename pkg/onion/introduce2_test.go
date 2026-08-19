package onion

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/opd-ai/go-tor/pkg/crypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

func TestComputeHSSubcredentialOfficial(t *testing.T) {
	// Appendix G 给出 N_hs_subcred，但未直接给 identity；此处验证公式自洽。
	id := make([]byte, 32)
	id[0] = 1
	blinded := ComputeBlindedPubkey(id, 1)
	sub := ComputeHSSubcredential(id, blinded)
	if len(sub) != 32 {
		t.Fatalf("len=%d", len(sub))
	}
	cred := ComputeHSCredential(id)
	h := sha3.New256()
	_, _ = h.Write([]byte("subcredential"))
	_, _ = h.Write(cred)
	_, _ = h.Write(blinded)
	want := h.Sum(nil)
	if !bytes.Equal(sub, want) {
		t.Fatal("subcredential mismatch")
	}
}

// TestParseIntroduce2OfficialVector 对照 rend-spec Appendix G.1 整包解密。
func TestParseIntroduce2OfficialVector(t *testing.T) {
	authKey := mustDecodeHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	bPriv := mustDecodeHex(t, "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	subcred := mustDecodeHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	xPriv := mustDecodeHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	B := mustDecodeHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")

	plaintext := mustDecodeHex(t, "6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCA"+
		"C4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F0000"+
		"0113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B"+
		"7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF870000000000"+
		"0000000000000000000000000000000000000000000000000000000000000000"+
		"000000000000000000000000000000000000000000000000000000000000")

	header := mustDecodeHex(t, "000000000000000000000000000000000000000002002034E171E4358E501BFF"+
		"21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00")

	encrypted, err := BuildIntroduce1Encrypted(header, plaintext, xPriv, B, authKey, subcred)
	if err != nil {
		t.Fatal(err)
	}
	cell := append(append([]byte{}, header...), encrypted...)

	req, err := ParseIntroduce2(cell, bPriv, subcred)
	if err != nil {
		t.Fatalf("ParseIntroduce2: %v", err)
	}
	if !bytes.Equal(req.IntroAuthKey, authKey) {
		t.Fatal("auth key mismatch")
	}
	wantX, _ := curve25519.X25519(xPriv, curve25519.Basepoint)
	if !bytes.Equal(req.ClientOnionKey, wantX) {
		t.Fatalf("X mismatch")
	}
	if len(req.RendezvousCookie) != 20 {
		t.Fatal("cookie")
	}
	if !bytes.Equal(req.RendezvousCookie, plaintext[:20]) {
		t.Fatal("cookie content")
	}
}

func TestParseIntroduce2RoundTrip(t *testing.T) {
	bPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	B, err := curve25519.X25519(bPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	authKey := make([]byte, 32)
	authKey[0] = 0xAB
	subcred := make([]byte, 32)
	subcred[1] = 0xCD

	cookie := bytes.Repeat([]byte{0x11}, 20)
	inner := make([]byte, 0)
	inner = append(inner, cookie...)
	inner = append(inner, 0x01) // nspec
	inner = append(inner, 0x00, 0x06, 192, 0, 2, 1, 0x1F, 0x90)
	inner = append(inner, 0x00)       // onion key type
	inner = append(inner, 0x00, 0x20) // len 32
	inner = append(inner, bytes.Repeat([]byte{0x22}, 32)...)
	inner = append(inner, 0x00) // no ext

	header := make([]byte, 0, 56)
	header = append(header, make([]byte, 20)...) // legacy
	header = append(header, 0x02, 0x00, 0x20)
	header = append(header, authKey...)
	header = append(header, 0x00) // n_ext

	enc, err := BuildIntroduce1Encrypted(header, inner, xPriv, B, authKey, subcred)
	if err != nil {
		t.Fatal(err)
	}
	cell := append(append([]byte{}, header...), enc...)
	req, err := ParseIntroduce2(cell, bPriv, subcred)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.RendezvousCookie, cookie) {
		t.Fatal("cookie")
	}
	addr, err := LinkSpecifierToAddress(req.LinkSpecifiers)
	if err != nil || addr != "192.0.2.1:8080" {
		t.Fatalf("addr=%q err=%v", addr, err)
	}
}

func TestParseIntroduce2BadMAC(t *testing.T) {
	bPriv, _ := crypto.GenerateCurve25519PrivateKey()
	B, _ := curve25519.X25519(bPriv, curve25519.Basepoint)
	xPriv, _ := crypto.GenerateCurve25519PrivateKey()
	authKey := bytes.Repeat([]byte{1}, 32)
	subcred := bytes.Repeat([]byte{2}, 32)
	header := append(append(make([]byte, 20), 0x02, 0x00, 0x20), append(authKey, 0x00)...)
	enc, err := BuildIntroduce1Encrypted(header, bytes.Repeat([]byte{3}, 40), xPriv, B, authKey, subcred)
	if err != nil {
		t.Fatal(err)
	}
	enc[len(enc)-1] ^= 0xff
	cell := append(header, enc...)
	if _, err := ParseIntroduce2(cell, bPriv, subcred); err == nil {
		t.Fatal("tampered MAC must fail")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
