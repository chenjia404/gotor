package relay

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestGenerateDescriptorPairCrossDigest(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	published := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	desc, extra, err := GenerateDescriptorPair(keys, &DescriptorConfig{
		Nickname:      "PairRelay",
		Address:       "192.0.2.20",
		ORPort:        9001,
		PublishedTime: published,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !desc.PublishedTime.Equal(extra.PublishedTime) {
		t.Fatalf("published mismatch desc=%v extra=%v", desc.PublishedTime, extra.PublishedTime)
	}
	raw := string(desc.RawDescriptor)
	if !strings.Contains(raw, "extra-info-digest ") {
		t.Fatal("server descriptor 必须交叉引用 extra-info-digest")
	}
	if strings.Contains(string(extra.RawDescriptor), "write-history") ||
		strings.Contains(string(extra.RawDescriptor), "read-history") {
		t.Fatal("无观测不得写 history")
	}

	const marker = "router-signature\n"
	idx := strings.Index(string(extra.RawDescriptor), marker)
	if idx < 0 {
		t.Fatal("extra-info missing router-signature")
	}
	wantSHA1 := sha1.Sum(extra.RawDescriptor[:idx+len(marker)]) // #nosec G401
	wantSHA256 := sha256.Sum256(extra.RawDescriptor)
	line := extraInfoDigestLine(raw)
	parts := strings.Fields(line)
	if len(parts) != 3 {
		t.Fatalf("extra-info-digest 要 SHA1+SHA256: %q", line)
	}
	if parts[1] != strings.ToUpper(hex.EncodeToString(wantSHA1[:])) {
		t.Fatalf("SHA1 mismatch got %s want %s", parts[1], hex.EncodeToString(wantSHA1[:]))
	}
	if parts[2] != base64.RawStdEncoding.EncodeToString(wantSHA256[:]) {
		t.Fatalf("SHA256 base64 mismatch got %s", parts[2])
	}
	if err := VerifyExtraInfoDocument(extra.RawDescriptor, keys.Ed25519Public, &keys.RSAPrivate.PublicKey); err != nil {
		t.Fatal(err)
	}
	bw := strings.Index(raw, "\nbandwidth ")
	ei := strings.Index(raw, "\nextra-info-digest ")
	onion := strings.Index(raw, "\nonion-key\n")
	if !(bw >= 0 && ei > bw && onion > ei) {
		t.Fatalf("extra-info-digest 应在 bandwidth 与 onion-key 之间")
	}
}

func TestGenerateDescriptorPairObservedHistoryOnly(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	stats := map[string]string{
		"write-history": "2026-08-20 12:15:00 (900 s) 400",
		"read-history":  "2026-08-20 12:15:00 (900 s) 1000",
	}
	_, extra, err := GenerateDescriptorPair(keys, &DescriptorConfig{
		Nickname: "ObsRelay",
		Address:  "192.0.2.21",
		ORPort:   9001,
	}, stats)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(extra.RawDescriptor)
	if !strings.Contains(raw, "write-history 2026-08-20 12:15:00 (900 s) 400\n") {
		t.Fatalf("missing write-history\n%s", raw)
	}
	if !strings.Contains(raw, "read-history 2026-08-20 12:15:00 (900 s) 1000\n") {
		t.Fatalf("missing read-history\n%s", raw)
	}
	w := strings.Index(raw, "write-history")
	r := strings.Index(raw, "read-history")
	if w < 0 || r < w {
		t.Fatal("write-history 应在 read-history 前")
	}
}

func TestGenerateServerDescriptorOmitsExtraInfoDigestWhenEmpty(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	desc, err := GenerateServerDescriptor(keys, &DescriptorConfig{
		Nickname: "NoEI",
		Address:  "192.0.2.22",
		ORPort:   9001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(desc.RawDescriptor), "extra-info-digest") {
		t.Fatal("未生成 extra-info 时不得写 extra-info-digest")
	}
}

func extraInfoDigestLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "extra-info-digest ") {
			return line
		}
	}
	return ""
}
