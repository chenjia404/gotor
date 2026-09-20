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
	if !strings.Contains(raw, "bandwidth 1048576 2097152 0\n") {
		t.Fatalf("无观测时 bandwidth 第三个数应为 0，不得抄 average\n%s", raw)
	}
	if strings.Contains(string(extra.RawDescriptor), "write-history") ||
		strings.Contains(string(extra.RawDescriptor), "read-history") ||
		strings.Contains(string(extra.RawDescriptor), "conn-bi-direct") ||
		strings.Contains(string(extra.RawDescriptor), "dirreq-v3-resp") ||
		strings.Contains(string(extra.RawDescriptor), "exit-stats-end") ||
		strings.Contains(string(extra.RawDescriptor), "hidserv-") {
		t.Fatal("无观测不得写 history / conn-bi-direct / dirreq / exit / hidserv")
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
		"write-history":                 "2026-08-20 12:15:00 (900 s) 400",
		"read-history":                  "2026-08-20 12:15:00 (900 s) 1000",
		"ipv6-write-history":            "2026-08-20 12:15:00 (900 s) 40",
		"ipv6-read-history":             "2026-08-20 12:15:00 (900 s) 100",
		"conn-bi-direct":                "2026-08-21 12:00:00 (86400 s) 10,2,1,3",
		"ipv6-conn-bi-direct":           "2026-08-21 12:00:00 (86400 s) 4,1,0,2",
		"dirreq-stats-end":              "2026-08-21 12:00:00 (86400 s)",
		"dirreq-v3-ips":                 "??=8",
		"dirreq-v3-reqs":                "??=8",
		"dirreq-v3-resp":                "ok=4,not-found=4",
		"dirreq-v3-direct-dl":           "complete=1",
		"dirreq-v3-tunneled-dl":         "complete=2",
		"exit-stats-end":                "2026-08-21 12:00:00 (86400 s)",
		"exit-kibibytes-written":        "80=1,other=1",
		"exit-kibibytes-read":           "80=2",
		"exit-streams-opened":           "80=4,other=4",
		"hidserv-v3-stats-end":          "2026-08-21 12:00:00 (86400 s)",
		"hidserv-rend-v3-relayed-cells": "1024 delta_f=2048 epsilon=0.30 binsize=1024",
		"hidserv-dir-v3-onions-seen":    "8 delta_f=8 epsilon=0.30 binsize=8",
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
	iw := strings.Index(raw, "ipv6-write-history 2026-08-20 12:15:00 (900 s) 40\n")
	if iw < 0 || iw < r {
		t.Fatal("ipv6-write-history 应在 read-history 后")
	}
	ir := strings.Index(raw, "ipv6-read-history 2026-08-20 12:15:00 (900 s) 100\n")
	if ir < 0 || ir < iw {
		t.Fatal("ipv6-read-history 应在 ipv6-write-history 后")
	}
	bidi := strings.Index(raw, "conn-bi-direct 2026-08-21 12:00:00 (86400 s) 10,2,1,3\n")
	if bidi < 0 || bidi < ir {
		t.Fatal("conn-bi-direct 应在 ipv6-read-history 后")
	}
	v6 := strings.Index(raw, "ipv6-conn-bi-direct 2026-08-21 12:00:00 (86400 s) 4,1,0,2\n")
	if v6 < 0 || v6 < bidi {
		t.Fatal("ipv6-conn-bi-direct 应在 conn-bi-direct 后")
	}
	ds := strings.Index(raw, "dirreq-stats-end 2026-08-21 12:00:00 (86400 s)\n")
	if ds < 0 || ds < v6 {
		t.Fatal("dirreq-stats-end 应在 ipv6-conn-bi-direct 后")
	}
	ips := strings.Index(raw, "dirreq-v3-ips ??=8\n")
	if ips < 0 || ips < ds {
		t.Fatal("dirreq-v3-ips 应在 dirreq-stats-end 后")
	}
	reqs := strings.Index(raw, "dirreq-v3-reqs ??=8\n")
	if reqs < 0 || reqs < ips {
		t.Fatal("dirreq-v3-reqs 应在 dirreq-v3-ips 后")
	}
	dr := strings.Index(raw, "dirreq-v3-resp ok=4,not-found=4\n")
	if dr < 0 || dr < reqs {
		t.Fatal("dirreq-v3-resp 应在 dirreq-v3-reqs 后")
	}
	dd := strings.Index(raw, "dirreq-v3-direct-dl complete=1\n")
	if dd < 0 || dd < dr {
		t.Fatal("dirreq-v3-direct-dl 应在 dirreq-v3-resp 后")
	}
	td := strings.Index(raw, "dirreq-v3-tunneled-dl complete=2\n")
	if td < 0 || td < dd {
		t.Fatal("dirreq-v3-tunneled-dl 应在 dirreq-v3-direct-dl 后")
	}
	es := strings.Index(raw, "exit-stats-end 2026-08-21 12:00:00 (86400 s)\n")
	if es < 0 || es < td {
		t.Fatal("exit-stats-end 应在 dirreq-v3-tunneled-dl 后")
	}
	ew := strings.Index(raw, "exit-kibibytes-written 80=1,other=1\n")
	if ew < 0 || ew < es {
		t.Fatal("exit-kibibytes-written 应在 exit-stats-end 后")
	}
	er := strings.Index(raw, "exit-kibibytes-read 80=2\n")
	if er < 0 || er < ew {
		t.Fatal("exit-kibibytes-read 应在 written 后")
	}
	eo := strings.Index(raw, "exit-streams-opened 80=4,other=4\n")
	if eo < 0 || eo < er {
		t.Fatal("exit-streams-opened 应在 read 后")
	}
	hs := strings.Index(raw, "hidserv-v3-stats-end 2026-08-21 12:00:00 (86400 s)\n")
	if hs < 0 || hs < eo {
		t.Fatal("hidserv-v3-stats-end 应在 exit-streams-opened 后")
	}
	hr := strings.Index(raw, "hidserv-rend-v3-relayed-cells 1024 delta_f=2048 epsilon=0.30 binsize=1024\n")
	if hr < 0 || hr < hs {
		t.Fatal("hidserv-rend-v3-relayed-cells 应在 hidserv-v3-stats-end 后")
	}
	ho := strings.Index(raw, "hidserv-dir-v3-onions-seen 8 delta_f=8 epsilon=0.30 binsize=8\n")
	if ho < 0 || ho < hr {
		t.Fatal("hidserv-dir-v3-onions-seen 应在 rend-v3-relayed-cells 后")
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
