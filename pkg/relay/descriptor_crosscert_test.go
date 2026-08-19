package relay

import (
	"strings"
	"testing"
)

// TestServerDescriptorCrosscertsAndSignatures 权威验收前的离线自检。
// 后续 AI / 其它人发描述符前应能复用 VerifyServerDescriptorDocument。
func TestServerDescriptorCrosscertsAndSignatures(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	desc, err := GenerateServerDescriptor(keys, &DescriptorConfig{
		Nickname: "CrossCertRelay",
		Address:  "192.0.2.10",
		ORPort:   9001,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(desc.RawDescriptor)
	for _, field := range []string{
		"onion-key-crosscert",
		"-----BEGIN CROSSCERT-----",
		"ntor-onion-key-crosscert ",
		"-----BEGIN ED25519 CERT-----",
		"router-sig-ed25519 ",
		"router-signature",
	} {
		if !strings.Contains(raw, field) {
			t.Fatalf("missing %q", field)
		}
	}
	if !strings.Contains(raw, "ntor-onion-key-crosscert 0") &&
		!strings.Contains(raw, "ntor-onion-key-crosscert 1") {
		t.Fatal("ntor-onion-key-crosscert Bit 必须是 0 或 1")
	}
	onionIdx := strings.Index(raw, "onion-key\n")
	crossIdx := strings.Index(raw, "onion-key-crosscert\n")
	ntorIdx := strings.Index(raw, "ntor-onion-key ")
	ntorCCIdx := strings.Index(raw, "ntor-onion-key-crosscert ")
	signIdx := strings.Index(raw, "signing-key\n")
	if !(onionIdx < crossIdx && crossIdx < ntorIdx && ntorIdx < ntorCCIdx && ntorCCIdx < signIdx) {
		t.Fatalf("字段顺序错误: onion=%d cross=%d ntor=%d ntorcc=%d sign=%d",
			onionIdx, crossIdx, ntorIdx, ntorCCIdx, signIdx)
	}
	if err := VerifyServerDescriptorDocument(desc.RawDescriptor, desc.Ed25519Identity, desc.RSAIdentity, desc.NtorOnionKey); err != nil {
		t.Fatalf("自检失败（权威会拒存）: %v\n%s", err, raw)
	}
}

func TestExtraInfoHasEd25519AndRSASignatures(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	desc, err := GenerateServerDescriptor(keys, &DescriptorConfig{
		Nickname: "ExtraSig",
		Address:  "192.0.2.11",
		ORPort:   9001,
	})
	if err != nil {
		t.Fatal(err)
	}
	extra, err := GenerateExtraInfo(keys, desc, map[string]string{"read-history": "x"})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(extra.RawDescriptor)
	for _, field := range []string{
		"identity-ed25519",
		"router-sig-ed25519 ",
		"router-signature",
		"-----BEGIN SIGNATURE-----",
	} {
		if !strings.Contains(raw, field) {
			t.Fatalf("extra-info missing %q", field)
		}
	}
	if extra.PublishedTime != desc.PublishedTime {
		t.Fatalf("extra-info published %v != descriptor %v", extra.PublishedTime, desc.PublishedTime)
	}
	if err := verifyRouterRSASig(extra.RawDescriptor, desc.RSAIdentity); err != nil {
		t.Fatalf("extra-info RSA: %v", err)
	}
}
