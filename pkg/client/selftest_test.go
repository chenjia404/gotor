package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
	"golang.org/x/crypto/curve25519"
)

func testSelfHop(t *testing.T, fp string) *directory.Relay {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var ntorPriv, ntorPub [32]byte
	if _, err := rand.Read(ntorPriv[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&ntorPub, &ntorPriv)
	rsaID := make([]byte, 20)
	if _, err := rand.Read(rsaID); err != nil {
		t.Fatal(err)
	}
	return &directory.Relay{
		Nickname:     "self",
		Fingerprint:  fp,
		Address:      "192.0.2.50",
		ORPort:       9001,
		RSAIdentity:  rsaID,
		IdentityKey:  edPriv.Public().(ed25519.PublicKey),
		NtorOnionKey: ntorPub[:],
	}
}

func TestAdvertisedORIPLiteral(t *testing.T) {
	ip, err := advertisedORIP("192.0.2.8")
	if err != nil || ip != "192.0.2.8" {
		t.Fatalf("got %q %v", ip, err)
	}
	ip, err = advertisedORIP("[2001:db8::1]")
	if err != nil || ip != "2001:db8::1" {
		t.Fatalf("v6 %q %v", ip, err)
	}
	if _, err := advertisedORIP("0.0.0.0"); err == nil {
		t.Fatal("unspecified 应拒绝")
	}
	if _, err := advertisedORIP(""); err == nil {
		t.Fatal("空地址应拒绝")
	}
}

func TestAttachTestingHop(t *testing.T) {
	self := testSelfHop(t, "aa")
	guard := &directory.Relay{Nickname: "g", Fingerprint: "g1", Address: "192.0.2.1", ORPort: 443}
	middle := &directory.Relay{Nickname: "m", Fingerprint: "m1", Address: "192.0.2.2", ORPort: 443}

	got, err := attachTestingHop(&path.Path{Guard: guard, Middle: middle}, self)
	if err != nil {
		t.Fatal(err)
	}
	if got.Exit != self || got.Guard != guard || got.Middle != middle {
		t.Fatal("末跳未换成 self")
	}

	if _, err := attachTestingHop(&path.Path{Guard: self, Middle: middle}, self); err == nil {
		t.Fatal("self 作 Guard 应拒绝")
	}
	if _, err := attachTestingHop(&path.Path{Guard: guard, Middle: self}, self); err == nil {
		t.Fatal("self 作 Middle 应拒绝")
	}
	if _, err := attachTestingHop(nil, self); err == nil {
		t.Fatal("空 path 应拒绝")
	}
	if _, err := attachTestingHop(&path.Path{Guard: guard, Middle: middle}, nil); err == nil {
		t.Fatal("空 self 应拒绝")
	}
}

func TestProbeORPortViaCircuitValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDirectory = t.TempDir()
	cfg.DisableNetwork = true
	c, err := New(cfg, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	self := testSelfHop(t, "bb")
	if err := c.ProbeORPortViaCircuit(context.Background(), self); err == nil {
		t.Fatal("DisableNetwork 应拒绝探测")
	}

	c.config.DisableNetwork = false
	if err := c.ProbeORPortViaCircuit(context.Background(), nil); err == nil {
		t.Fatal("nil self 应拒绝")
	}
	bad := *self
	bad.NtorOnionKey = nil
	if err := c.ProbeORPortViaCircuit(context.Background(), &bad); err == nil {
		t.Fatal("缺密钥应拒绝")
	}
	if err := c.ProbeORPortViaCircuit(context.Background(), self); err == nil {
		t.Fatal("未启动的 path selector 应拒绝")
	}
}
