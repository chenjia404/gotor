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
