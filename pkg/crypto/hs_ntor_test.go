package crypto

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func mustHexHS(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHsMACTorVector 对照 Arti/C Tor 已知向量。
func TestHsMACTorVector(t *testing.T) {
	key := []byte("i'm from the past talking to the future.")
	msg := []byte("i am in a library somewhere using my computer")
	want := mustHex(t, "753fba6d87d49497238a512a3772dd291e55f7d1cd332c9fb5c967c7a10a13ca")
	got := HsMAC(key, msg)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

// TestHsNtorOfficialIntroKeys 对照 rend-spec Appendix G.1。
func TestHsNtorOfficialIntroKeys(t *testing.T) {
	authKey := mustHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	B := mustHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	bPriv := mustHex(t, "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	subcred := mustHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	xPriv := mustHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	wantX := mustHex(t, "BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")
	wantEnc := mustHex(t, "9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706")
	wantMac := mustHex(t, "FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5")

	// 确认 bPriv → B
	gotB, err := curve25519.X25519(bPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(gotB) != hex.EncodeToString(B) {
		t.Fatalf("B from bPriv mismatch")
	}

	enc, mac, X, err := HsNtorClientIntroKeys(xPriv, B, authKey, subcred)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(X) != hex.EncodeToString(wantX) {
		t.Fatalf("X=%x want %x", X, wantX)
	}
	if hex.EncodeToString(enc) != hex.EncodeToString(wantEnc) {
		t.Fatalf("ENC_KEY=%x want %x", enc, wantEnc)
	}
	if hex.EncodeToString(mac) != hex.EncodeToString(wantMac) {
		t.Fatalf("MAC_KEY=%x want %x", mac, wantMac)
	}

	// 服务端应得到相同 ENC/MAC
	senc, smac, _, err := HsNtorServiceIntroKeys(bPriv, X, authKey, subcred)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(senc) != hex.EncodeToString(wantEnc) || hex.EncodeToString(smac) != hex.EncodeToString(wantMac) {
		t.Fatalf("service intro keys mismatch")
	}
}

// TestHsNtorOfficialRend 对照 Appendix G.1 RENDEZVOUS 阶段。
func TestHsNtorOfficialRend(t *testing.T) {
	authKey := mustHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	B := mustHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	bPriv := mustHex(t, "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	xPriv := mustHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	X := mustHex(t, "BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")
	yPriv := mustHex(t, "68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55")
	wantY := mustHex(t, "8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700")
	wantAuth := mustHex(t, "4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208")
	wantSeed := mustHex(t, "4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")

	resp, seed, err := HsNtorServiceRend(yPriv, bPriv, X, authKey)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(resp[:32]) != hex.EncodeToString(wantY) {
		t.Fatalf("Y=%x want %x", resp[:32], wantY)
	}
	if hex.EncodeToString(resp[32:]) != hex.EncodeToString(wantAuth) {
		t.Fatalf("AUTH=%x want %x", resp[32:], wantAuth)
	}
	if hex.EncodeToString(seed) != hex.EncodeToString(wantSeed) {
		t.Fatalf("SEED=%x want %x", seed, wantSeed)
	}

	clientSeed, err := HsNtorClientRend(xPriv, B, authKey, resp)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(clientSeed) != hex.EncodeToString(wantSeed) {
		t.Fatalf("client seed=%x want %x", clientSeed, wantSeed)
	}

	keys, err := HsNtorExpandCircuitKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != HsNtorCircuitKeyLen {
		t.Fatalf("key material len=%d", len(keys))
	}
}

func TestHsNtorClientRendRejectsBadAuth(t *testing.T) {
	authKey := mustHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	B := mustHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	bPriv := mustHex(t, "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	xPriv := mustHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	X := mustHex(t, "BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")
	yPriv := mustHex(t, "68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55")
	resp, _, err := HsNtorServiceRend(yPriv, bPriv, X, authKey)
	if err != nil {
		t.Fatal(err)
	}
	resp[40] ^= 0xff
	if _, err := HsNtorClientRend(xPriv, B, authKey, resp); err == nil {
		t.Fatal("tampered AUTH must fail")
	}
}
