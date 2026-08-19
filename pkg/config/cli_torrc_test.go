package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCLI_FlagsAndPositional(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	content := "SocksPort 9055\nControlPort 9056\nCookieAuthentication 1\nUnknownOption foo\n"
	if err := os.WriteFile(torrc, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ParseCLI([]string{"-f", torrc, "SocksPort", "9150"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.SocksPort != 9150 {
		t.Fatalf("SocksPort override: got %d", res.Config.SocksPort)
	}
	if res.Config.ControlPort != 9056 {
		t.Fatalf("ControlPort: got %d", res.Config.ControlPort)
	}
	if !res.Config.CookieAuthentication {
		t.Fatal("CookieAuthentication expected")
	}
}

func TestLoadTorrcClientOptions(t *testing.T) {
	dir := t.TempDir()
	hsDir := filepath.Join(dir, "hs")
	torrc := filepath.Join(dir, "torrc")
	body := "SocksPort 127.0.0.1:9060 IsolateDestinations\n" +
		"Log notice file " + filepath.Join(dir, "tor.log") + "\n" +
		"HiddenServiceDir " + hsDir + "\n" +
		"HiddenServicePort 80 127.0.0.1:8080\n" +
		"ExitNodes $AAAA,$BBBB\n" +
		"StrictNodes 1\n" +
		"HashedControlPassword 16:660537E3E1CD49996044A3BF558097A981F539FEA2F9DA662B4626C1C2\n"
	if err := os.WriteFile(torrc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := LoadFromFile(torrc, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SocksPort != 9060 || cfg.SocksListenAddr != "127.0.0.1" {
		t.Fatalf("socks %s:%d", cfg.SocksListenAddr, cfg.SocksPort)
	}
	if !cfg.IsolateDestinations {
		t.Fatal("IsolateDestinations")
	}
	if cfg.LogLevel != "info" || cfg.LogFile == "" {
		t.Fatalf("log %s %s", cfg.LogLevel, cfg.LogFile)
	}
	if len(cfg.OnionServices) != 1 {
		t.Fatalf("onion services %d", len(cfg.OnionServices))
	}
	osvc := cfg.OnionServices[0]
	if osvc.ServiceDir != hsDir || osvc.VirtualPort != 80 || osvc.TargetAddr != "127.0.0.1:8080" {
		t.Fatalf("%+v", osvc)
	}
	if len(cfg.ExitNodes) != 2 || !cfg.StrictNodes {
		t.Fatalf("exitnodes %+v strict %v", cfg.ExitNodes, cfg.StrictNodes)
	}
	if cfg.HashedControlPassword == "" {
		t.Fatal("hashed password")
	}
}

func TestIncludeTorrc(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "extra.torrc")
	main := filepath.Join(dir, "torrc")
	if err := os.WriteFile(inc, []byte("ControlPort 9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("%include extra.torrc\nSocksPort 9050\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := LoadFromFile(main, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPort != 9999 {
		t.Fatalf("ControlPort %d", cfg.ControlPort)
	}
}

func TestParseCLI_LegacyFlagsOverrideTorrc(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	if err := os.WriteFile(torrc, []byte("SocksPort 9055\nControlPort 9056\nDataDirectory /tmp/from-torrc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ParseCLI([]string{"-f", torrc, "-socks-port", "9150", "-control-port", "9151", "-data-dir", "/tmp/from-cli"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.SocksPort != 9150 || res.Config.ControlPort != 9151 {
		t.Fatalf("legacy flags must override torrc: socks=%d control=%d", res.Config.SocksPort, res.Config.ControlPort)
	}
	if res.Config.DataDirectory != "/tmp/from-cli" {
		t.Fatalf("data-dir override: %s", res.Config.DataDirectory)
	}
}

func TestParseCLI_HiddenServicePositional(t *testing.T) {
	dir := t.TempDir()
	hs := filepath.Join(dir, "hs")
	res, err := ParseCLI([]string{
		"SocksPort", "9070",
		"HiddenServiceDir", hs,
		"HiddenServicePort", "80", "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Config.OnionServices) != 1 {
		t.Fatalf("onion services: %d", len(res.Config.OnionServices))
	}
	osvc := res.Config.OnionServices[0]
	if osvc.ServiceDir != hs || osvc.VirtualPort != 80 || osvc.TargetAddr != "127.0.0.1:8080" {
		t.Fatalf("%+v", osvc)
	}
}
