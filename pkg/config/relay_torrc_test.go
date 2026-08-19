package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTorrcRelayOptions(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	body := "ORPort 0.0.0.0:9001\nNickname TestRelay\nExitRelay 0\n" +
		"PublishServerDescriptor 0\nAssumeReachable 1\nContactInfo a@b.c\n" +
		"Address 203.0.113.10\nRelayBandwidthRate 1 MB\nRelayBandwidthBurst 2 MB\n"
	if err := os.WriteFile(torrc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := LoadFromFile(torrc, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ORPort != 9001 || cfg.ORListenAddr != "0.0.0.0" {
		t.Fatalf("ORPort %s:%d", cfg.ORListenAddr, cfg.ORPort)
	}
	if cfg.Nickname != "TestRelay" || cfg.ExitRelay || cfg.PublishServerDescriptor {
		t.Fatalf("nickname/exit/publish: %+v %+v %+v", cfg.Nickname, cfg.ExitRelay, cfg.PublishServerDescriptor)
	}
	if !cfg.AssumeReachable || cfg.ContactInfo != "a@b.c" || cfg.RelayAddress != "203.0.113.10" {
		t.Fatal("address/contact/assume")
	}
	if cfg.RelayBandwidthRate != 1<<20 || cfg.RelayBandwidthBurst != 2<<20 {
		t.Fatalf("bw rate=%d burst=%d", cfg.RelayBandwidthRate, cfg.RelayBandwidthBurst)
	}
}
