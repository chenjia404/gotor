package onion

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestBlindedSigningVerifiesAgainstBlindedPubkey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	period := GetTimePeriod(time.Now())
	mat, err := DeriveBlindedSigningMaterial(priv, period)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("cert-body-for-test")
	sig, err := mat.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(mat.PublicKey, msg, sig) {
		t.Fatal("blinded signature failed verification")
	}
	want := ComputeBlindedPubkey(priv.Public().(ed25519.PublicKey), period)
	if string(want) != string(mat.PublicKey) {
		t.Fatal("public key mismatch")
	}
}

func TestSealDescriptorRoundTripDecryptAndVerify(t *testing.T) {
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
		RevisionCounter: 7,
		Lifetime:        3 * time.Hour,
		IntroPoints: []IntroductionPoint{{
			LinkSpecifiers: []LinkSpecifier{{Type: 0, Data: []byte{1, 2, 3, 4, 0, 80}}},
			OnionKey:       make([]byte, 32),
			AuthKey:        make([]byte, 32),
			EncKey:         make([]byte, 32),
		}},
	}
	copy(desc.IntroPoints[0].OnionKey, pub)
	copy(desc.IntroPoints[0].AuthKey, pub)
	copy(desc.IntroPoints[0].EncKey, pub[:32])

	if err := (&Service{identityKey: priv, address: addr}).signDescriptor(desc); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(desc.SuperencryptedBlob) == 0 {
		t.Fatal("missing superencrypted blob")
	}
	if len(desc.DescriptorSigningKeyCert) < 40 {
		t.Fatal("missing type8 cert")
	}
	if desc.DescriptorSigningKeyCert[1] != 8 {
		t.Fatalf("cert type %d want 8", desc.DescriptorSigningKeyCert[1])
	}

	parsed, err := ParseDescriptor(desc.RawDescriptor)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsed.BlindedPubkey = blinded
	if err := VerifyDescriptorSignature(parsed, addr); err != nil {
		t.Fatalf("verify: %v", err)
	}

	dec, err := DecryptDescriptor(parsed, addr, period)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(dec.IntroPoints) == 0 {
		t.Fatal("expected intro points after decrypt")
	}
}
