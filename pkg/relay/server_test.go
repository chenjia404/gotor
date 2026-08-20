package relay

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestNewServerFromConfigAndListen(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := config.DefaultConfig()
	cfg.DataDirectory = dir
	cfg.ORPort = port
	cfg.ORListenAddr = "127.0.0.1"
	cfg.Nickname = "testmiddle"
	cfg.ExitRelay = false
	cfg.PublishServerDescriptor = false

	srv, err := NewServerFromConfig(cfg, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	if srv.Fingerprint() == "" || len(srv.Fingerprint()) != 40 {
		t.Fatalf("fingerprint %q", srv.Fingerprint())
	}
	if _, err := LoadKeys(filepath.Join(dir, "keys")); err != nil {
		t.Fatalf("reload keys: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
}

func TestServerReachabilityAssumeReachable(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := config.DefaultConfig()
	cfg.DataDirectory = dir
	cfg.ORPort = port
	cfg.ORListenAddr = "127.0.0.1"
	cfg.RelayAddress = "192.0.2.1"
	cfg.Nickname = "assumeRel"
	cfg.PublishServerDescriptor = true
	cfg.AssumeReachable = true

	srv, err := NewServerFromConfig(cfg, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	// 不 Start：避免向权威 POST。只检查门闩与 TestingHop。
	hop := srv.TestingHop()
	if hop == nil || !hop.HasExtendKeys() {
		t.Fatal("TestingHop 无效")
	}
	if hop.HasFlag("Running") {
		t.Fatal("TestingHop 不得带 Running")
	}
	st := srv.ReachabilityStatus()
	if !st.Assumed || !st.CanPublish {
		t.Fatalf("AssumeReachable+Publish 应允许发布: %+v", st)
	}
}

func TestNtorKeyPersistedAcrossLoad(t *testing.T) {
	dir := t.TempDir()
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveKeys(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.NtorOnionKey) != 32 {
		t.Fatalf("ntor key missing after load")
	}
	if string(loaded.NtorOnionKey) != string(keys.NtorOnionKey) {
		t.Fatal("ntor key changed across save/load")
	}
}
