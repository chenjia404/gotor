package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestInSameFamilyByFamilyID(t *testing.T) {
	a := &Relay{Fingerprint: "AA", Nickname: "a", FamilyIDs: []string{"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	b := &Relay{Fingerprint: "BB", Nickname: "b", FamilyIDs: []string{"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	c := &Relay{Fingerprint: "CC", Nickname: "c", FamilyIDs: []string{"ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}}

	if !a.InSameFamily(b) {
		t.Fatal("共享 family-ids 必须视为同家族（无需双向 family 列表）")
	}
	if !b.InSameFamily(a) {
		t.Fatal("family-ids 判断必须对称")
	}
	if a.InSameFamily(c) {
		t.Fatal("不同 family-ids 不得视为同家族")
	}
}

func TestInSameFamilyIDDoesNotRequireLists(t *testing.T) {
	a := &Relay{Fingerprint: "AA", FamilyIDs: []string{"ed25519:SHARED"}}
	b := &Relay{Fingerprint: "BB", FamilyIDs: []string{"ed25519:SHARED"}}
	if !a.InSameFamilyPolicy(b, true, false) {
		t.Fatal("use-family-ids=1 时应只靠 ID")
	}
	if a.InSameFamilyPolicy(b, false, true) {
		t.Fatal("use-family-ids=0 且无双向列表时不得匹配")
	}
}

func TestInSameFamilyHexDollarList(t *testing.T) {
	a := &Relay{
		Fingerprint:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		FingerprintHex: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Family:         []string{"$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
	}
	b := &Relay{
		Fingerprint:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		FingerprintHex: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		Family:         []string{"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=name"},
	}
	if !a.InSameFamily(b) {
		t.Fatal("$HEX 与 $HEX=name 的双向 family 列表应匹配")
	}
}

func TestFamilyPolicyFromParams(t *testing.T) {
	ids, lists := FamilyPolicyFromParams(nil)
	if !ids || !lists {
		t.Fatal("缺省必须都是 1")
	}
	ids, lists = FamilyPolicyFromParams(map[string]int{"use-family-ids": 0, "use-family-lists": 1})
	if ids || !lists {
		t.Fatalf("got ids=%v lists=%v", ids, lists)
	}
}

func TestParseMicrodescriptorFamilyIDs(t *testing.T) {
	ntor := base64.StdEncoding.EncodeToString(bytesRepeat(0x42, 32))
	ed := base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	doc := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIB\n-----END RSA PUBLIC KEY-----\n" +
		"ntor-onion-key " + ntor + "\n" +
		"id ed25519 " + ed + "\n" +
		"family $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"family-ids ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA unrecognized:xyz\n"

	sum := sha256.Sum256([]byte(doc))
	digest := base64.RawStdEncoding.EncodeToString(sum[:])
	relay := &Relay{Nickname: "Fam", MicrodescDigest: digest}
	client := NewClient(nil)
	if err := client.parseMicrodescriptors([]byte(doc), map[string][]*Relay{digest: {relay}}); err != nil {
		t.Fatal(err)
	}
	if len(relay.FamilyIDs) != 2 || relay.FamilyIDs[0] != "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("FamilyIDs = %#v", relay.FamilyIDs)
	}
	if relay.FamilyIDs[1] != "unrecognized:xyz" {
		t.Fatal("应接受未识别格式的 family ID")
	}
}

func TestInSameFamilyNilSafe(t *testing.T) {
	var a *Relay
	b := &Relay{Fingerprint: "X"}
	if a.InSameFamily(b) || b.InSameFamily(nil) {
		t.Fatal("nil 不得视为同家族")
	}
}

func TestInSameFamilyHexTildeList(t *testing.T) {
	a := &Relay{
		Fingerprint:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		FingerprintHex: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Family:         []string{"$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~nick"},
	}
	b := &Relay{
		Fingerprint:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		FingerprintHex: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		Family:         []string{"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	if !a.InSameFamily(b) {
		t.Fatal("$HEX~name 与 $HEX 的双向 family 列表应匹配")
	}
}

func TestParseFamilyIDsDedup(t *testing.T) {
	got := parseFamilyIDs([]string{"ed25519:AAAA", "ed25519:AAAA", "ed25519:BBBB", ""})
	if len(got) != 2 || got[0] != "ed25519:AAAA" || got[1] != "ed25519:BBBB" {
		t.Fatalf("dedup 失败: %#v", got)
	}
}

func TestShareFamilyIDIgnoresEmpty(t *testing.T) {
	if shareFamilyID([]string{"", " "}, []string{"ed25519:X"}) {
		t.Fatal("空 ID 不得匹配")
	}
	if shareFamilyID([]string{"ed25519:X"}, []string{"ed25519:Y"}) {
		t.Fatal("不同 ID 不得匹配")
	}
}

func TestInSameFamilyByEd25519Identity(t *testing.T) {
	key := bytesRepeat(0x11, 32)
	a := &Relay{Fingerprint: "AA", IdentityKey: key}
	b := &Relay{Fingerprint: "BB", IdentityKey: append([]byte(nil), key...)}
	if !a.InSameFamily(b) {
		t.Fatal("相同 Ed25519 身份必须视为同一继电器/同家族")
	}
}
