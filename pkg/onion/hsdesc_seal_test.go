package onion

import (
	"bytes"
	"crypto/ed25519"
	"strings"
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

func TestCTorHSDirPlaintextWireFormat(t *testing.T) {
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
			LinkSpecifiers: []LinkSpecifier{{Type: 0, Data: []byte{192, 0, 2, 1, 0, 80}}},
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

	sigB64 := descriptorSignatureLine(desc.RawDescriptor)
	if len(sigB64) != 86 {
		t.Fatalf("signature base64 长度 %d，C Tor ED25519_SIG_BASE64_LEN 要 86", len(sigB64))
	}
	if strings.Contains(sigB64, "=") {
		t.Fatal("signature 不得带 padding，否则 HSDir desc_sig_is_valid 直接拒收")
	}
	if descriptorSignatureBase64Len(desc) != 86 {
		t.Fatalf("sig_b64_len=%d want 86", descriptorSignatureBase64Len(desc))
	}
	if _, _, _, err := VerifyHSDirOuterDescriptor(desc.RawDescriptor); err != nil {
		t.Fatalf("VerifyHSDirOuterDescriptor: %v", err)
	}

	blob := desc.SuperencryptedBlob
	const overhead = hsDescSaltLen + hsDescMACLen
	if len(blob) <= overhead || (len(blob)-overhead)%hsDescSuperencPlaintextPadMultiple != 0 {
		t.Fatalf("superencrypted blob %d 不是 salt+10k*N+mac", len(blob))
	}

	subcred := ComputeHSSubcredential(addr.Pubkey, blinded)
	outerPlain, err := decryptHSDescLayer(blob, blinded, subcred, desc.RevisionCounter, "hsdir-superencrypted-data")
	if err != nil {
		t.Fatalf("decrypt outer: %v", err)
	}
	got := bytes.Count(outerPlain, []byte("auth-client "))
	if got != hsDescAuthClientDummyCount {
		t.Fatalf("auth-client 行数 %d want %d", got, hsDescAuthClientDummyCount)
	}
}

func TestPadHSDescSuperencryptedPlaintext(t *testing.T) {
	if got := padHSDescSuperencryptedPlaintext(nil); len(got) != hsDescSuperencPlaintextPadMultiple {
		t.Fatalf("empty pad %d", len(got))
	}
	small := []byte("hello")
	got := padHSDescSuperencryptedPlaintext(small)
	if len(got) != hsDescSuperencPlaintextPadMultiple || !bytes.HasPrefix(got, small) {
		t.Fatalf("small pad %d prefix=%q", len(got), got[:5])
	}
	exact := make([]byte, hsDescSuperencPlaintextPadMultiple)
	if p := padHSDescSuperencryptedPlaintext(exact); len(p) != hsDescSuperencPlaintextPadMultiple {
		t.Fatalf("exact pad %d", len(p))
	}
	over := make([]byte, hsDescSuperencPlaintextPadMultiple+1)
	if p := padHSDescSuperencryptedPlaintext(over); len(p) != 2*hsDescSuperencPlaintextPadMultiple {
		t.Fatalf("over pad %d", len(p))
	}
}

func descriptorSignatureLine(raw []byte) string {
	idx := bytes.Index(raw, []byte("\nsignature "))
	if idx < 0 {
		return ""
	}
	line := raw[idx+len("\nsignature "):]
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return string(bytes.TrimSpace(line))
}
