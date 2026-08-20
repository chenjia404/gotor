package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestLoadTorrcExitPolicy(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	body := "ORPort 9001\nExitRelay 1\nReduceExitPolicy 1\nIPv6Exit 0\n" +
		"ExitPolicy accept *:80\nExitPolicy accept *:443\nExitPolicy reject *:*\n"
	if err := os.WriteFile(torrc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := LoadFromFile(torrc, cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.ExitRelay || !cfg.ReduceExitPolicy || cfg.IPv6Exit {
		t.Fatal("exit flags")
	}
	if len(cfg.ExitPolicyLines) < 3 {
		t.Fatalf("ExitPolicy lines %d", len(cfg.ExitPolicyLines))
	}
}

func TestLoadTorrcExitRelayExtendedKeys(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	body := "ORPort 9001\nExitRelay 1\nDirPort 9030\nDirCache 1\n" +
		"ExitPolicyRejectPrivate 1\nExitPolicyRejectLocalInterfaces 1\n" +
		"MyFamily $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"FamilyID ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"SocksPort 0\n"
	if err := os.WriteFile(torrc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultCLIConfig()
	if err := LoadFromFile(torrc, cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.ExitRelay || cfg.DirPort != 9030 || !cfg.DirCache {
		t.Fatalf("exit/dir %+v", cfg)
	}
	if !cfg.ExitPolicyRejectPrivate || !cfg.ExitPolicyRejectLocalInterfaces {
		t.Fatal("reject private/local")
	}
	if len(cfg.MyFamily) != 1 || len(cfg.FamilyIDs) != 1 {
		t.Fatalf("family %v %v", cfg.MyFamily, cfg.FamilyIDs)
	}
	if cfg.SocksPort != 0 {
		t.Fatal("SocksPort 0")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.CheckDropInConstraints(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTorrcDoSOfficialKeys(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	body := "DoSCircuitCreationEnabled 1\nDoSCircuitCreationMinConnections 4\n" +
		"DoSCircuitCreationRate 5\nDoSCircuitCreationBurst 10\n" +
		"DoSCircuitCreationDefenseTimePeriod 3600 seconds\n" +
		"DoSConnectionEnabled auto\nDoSConnectionMaxConcurrentCount 50\n" +
		"DoSRefuseSingleHopClient 1\nConnLimit 2000\n"
	if err := os.WriteFile(torrc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := LoadFromFile(torrc, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DoSCircuitCreationEnabled != DoSEnabledOn {
		t.Fatalf("circ enabled %d", cfg.DoSCircuitCreationEnabled)
	}
	if cfg.DoSCircuitCreationMinConnections != 4 || cfg.DoSCircuitCreationRate != 5 || cfg.DoSCircuitCreationBurst != 10 {
		t.Fatalf("circ params %+v", cfg)
	}
	if cfg.DoSCircuitCreationDefenseTime != time.Hour {
		t.Fatalf("defense %s", cfg.DoSCircuitCreationDefenseTime)
	}
	if cfg.DoSConnectionEnabled != DoSEnabledAuto {
		t.Fatalf("conn enabled %d", cfg.DoSConnectionEnabled)
	}
	if cfg.DoSConnectionMaxConcurrentCount != 50 || !cfg.DoSRefuseSingleHopClient {
		t.Fatal("conn/refuse")
	}
	if cfg.ConnLimit != 2000 {
		t.Fatalf("ConnLimit 语义被改写: %d", cfg.ConnLimit)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDirPortAutoPicksFreePort(t *testing.T) {
	cfg := DefaultCLIConfig()
	if err := processConfigOption(cfg, "DirPort", "auto", nil); err != nil {
		t.Fatal(err)
	}
	if cfg.DirPort <= 0 {
		t.Fatalf("DirPort auto 应选空闲端口，得到 %d", cfg.DirPort)
	}
}
