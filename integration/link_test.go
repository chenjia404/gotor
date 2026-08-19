//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/connection"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/protocol"
)

func TestRealLinkHandshake(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dir := directory.NewClient(log)
	relays, err := dir.FetchConsensus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var guard *directory.Relay
	for _, r := range relays {
		if r.IsGuard() && r.IsRunning() && r.ORPort > 0 && r.GetFingerprintHex() != "" {
			guard = r
			break
		}
	}
	if guard == nil {
		t.Fatal("no guard in consensus")
	}

	cfg := connection.DefaultConfig(fmt.Sprintf("%s:%d", guard.Address, guard.ORPort))
	cfg.ExpectedFingerprint = guard.GetFingerprintHex()
	cfg.RequireCERTS = true
	if len(guard.IdentityKey) == 32 {
		cfg.ExpectedIdentity = guard.IdentityKey
	}
	conn := connection.New(cfg, log)
	if err := conn.Connect(ctx, cfg); err != nil {
		t.Fatalf("TLS: %v", err)
	}
	defer conn.Close()

	hs := protocol.NewHandshake(conn, log)
	if err := hs.PerformHandshake(ctx); err != nil {
		t.Fatalf("link handshake guard=%s fp=%s: %v", guard.Nickname, guard.GetFingerprintHex(), err)
	}
	if hs.NegotiatedVersion() < 3 {
		t.Fatalf("unexpected link version %d", hs.NegotiatedVersion())
	}
	t.Logf("Link Ready guard=%s version=%d fp=%s", guard.Nickname, hs.NegotiatedVersion(), guard.GetFingerprintHex())
}

// TestRealCertsType7RSA 验收 type 7 必须由 type 2 RSA identity 交叉签名。
// RequireCERTS=true 时握手失败即表示实网 type 7 PKCS#1 校验未通过。
func TestRealCertsType7RSA(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dir := directory.NewClient(log)
	relays, err := dir.FetchConsensus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var guard *directory.Relay
	for _, r := range relays {
		if r.IsGuard() && r.IsRunning() && r.ORPort > 0 && r.GetFingerprintHex() != "" {
			guard = r
			break
		}
	}
	if guard == nil {
		t.Fatal("no guard in consensus")
	}
	if err := dir.FetchMicrodescriptorsFor(ctx, []*directory.Relay{guard}); err != nil {
		t.Fatal(err)
	}

	cfg := connection.DefaultConfig(fmt.Sprintf("%s:%d", guard.Address, guard.ORPort))
	cfg.ExpectedFingerprint = guard.GetFingerprintHex()
	cfg.RequireCERTS = true
	if len(guard.IdentityKey) == 32 {
		cfg.ExpectedIdentity = guard.IdentityKey
	}
	conn := connection.New(cfg, log)
	if err := conn.Connect(ctx, cfg); err != nil {
		t.Fatalf("TLS: %v", err)
	}
	defer conn.Close()

	hs := protocol.NewHandshake(conn, log)
	if err := hs.PerformHandshake(ctx); err != nil {
		t.Fatalf("type 7 RSA cross-cert handshake failed guard=%s: %v", guard.Nickname, err)
	}
	edPrefix := []byte(nil)
	if len(guard.IdentityKey) >= 8 {
		edPrefix = guard.IdentityKey[:8]
	}
	t.Logf("type 7 RSA cross-cert OK guard=%s fp=%s ed=%x", guard.Nickname, guard.GetFingerprintHex(), edPrefix)
}
