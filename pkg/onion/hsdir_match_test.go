package onion

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestMatchHSDirDescriptor(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := &Address{Pubkey: []byte(pub)}
	period := GetTimePeriod(time.Now())
	blinded := ComputeBlindedPubkey(pub, period)
	desc := &Descriptor{
		Version:         3,
		Address:         addr,
		BlindedPubkey:   blinded,
		RevisionCounter: 1,
		Lifetime:        3 * time.Hour,
		IntroPoints: []IntroductionPoint{{
			LinkSpecifiers: []LinkSpecifier{{Type: 0, Data: []byte{1, 2, 3, 4, 0, 80}}},
			OnionKey:       make([]byte, 32),
			AuthKey:        make([]byte, 32),
			EncKey:         make([]byte, 32),
		}},
	}
	if err := (&Service{identityKey: priv, address: addr}).signDescriptor(desc); err != nil {
		t.Fatal(err)
	}
	if !MatchHSDirDescriptor(desc.RawDescriptor, blinded) {
		t.Fatal("type-8 证书应由该盲化公钥签发")
	}
	other := make([]byte, 32)
	other[0] = 1
	if MatchHSDirDescriptor(desc.RawDescriptor, other) {
		t.Fatal("其它盲化公钥不得命中")
	}
	if MatchHSDirDescriptor([]byte("hs-descriptor 3\n"), blinded) {
		t.Fatal("无证书不得命中")
	}
	if _, _, err := VerifyHSDirOuterDescriptor(desc.RawDescriptor); err != nil {
		t.Fatalf("验签外层: %v", err)
	}
	tampered := append([]byte(nil), desc.RawDescriptor...)
	if i := bytes.Index(tampered, []byte("revision-counter")); i >= 0 {
		tampered[i] ^= 0x01
	}
	if _, _, err := VerifyHSDirOuterDescriptor(tampered); err == nil {
		t.Fatal("改正文必须验签失败")
	}
}

func TestParseLinkSpecifiersCapsUserLength(t *testing.T) {
	intro := &IntroductionPoint{}
	// nspec=255、LSLEN=255，正文只有 3 字节，不得按声明长度分配。
	parseLinkSpecifiers([]byte{255, 0, 255, 1, 2}, intro)
	if len(intro.LinkSpecifiers) != 0 {
		t.Fatalf("超长 link specifier 不得入库, got %d", len(intro.LinkSpecifiers))
	}
	ok := &IntroductionPoint{}
	parseLinkSpecifiers([]byte{1, 0, 6, 192, 0, 2, 1, 0, 80}, ok)
	if len(ok.LinkSpecifiers) != 1 || len(ok.LinkSpecifiers[0].Data) != 6 {
		t.Fatalf("合法 IPv4 specifier 应解析, got %+v", ok.LinkSpecifiers)
	}
}
