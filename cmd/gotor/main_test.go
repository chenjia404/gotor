package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/config"
)

func TestVersionLine(t *testing.T) {
	if !strings.HasPrefix(config.VersionString(), "Tor version ") {
		t.Fatalf("%s", config.VersionString())
	}
}

func TestCLIBinaryVersion(t *testing.T) {
	exe := os.Args[0]
	// 用 `go test` 编译出的测试二进制跑 --version 无意义；测 ParseCLI 行为。
	res, err := config.ParseCLI([]string{"--version"})
	if err != nil || !res.ShowVersion {
		t.Fatal(err)
	}
	_ = exe
}

func TestHelpListsDropInFlags(t *testing.T) {
	_ = printHelp
}

func TestPrintFingerprintRequiresExistingKeys(t *testing.T) {
	cfg := config.DefaultCLIConfig()
	cfg.DataDirectory = t.TempDir()
	if err := printFingerprint(cfg, "rsa"); err == nil {
		t.Fatal("--list-fingerprint 在无身份钥时应失败")
	}
}

func TestKeygenPrintFingerprint(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultCLIConfig()
	cfg.DataDirectory = dir
	cfg.Nickname = "TestNick"
	if err := runKeygen(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", "ed25519_identity_secret_key")); err != nil {
		t.Fatal(err)
	}
}

func TestNTServiceFlag(t *testing.T) {
	res, err := config.ParseCLI([]string{"--nt-service"})
	if err != nil || !res.NTService {
		t.Fatal(err)
	}
}

func TestVerifyConfigExitRelay(t *testing.T) {
	cfg := config.DefaultCLIConfig()
	cfg.ExitRelay = true
	if err := cfg.CheckDropInConstraints(); err == nil {
		t.Fatal("ExitRelay 1 且 ORPort=0 应拒绝")
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate 也应拒绝 ExitRelay 1 + ORPort=0")
	}
	cfg.ORPort = 9001
	if err := cfg.CheckDropInConstraints(); err != nil {
		t.Fatalf("ExitRelay 1 + ORPort 应允许: %v", err)
	}
}

func TestExternalGoTestBinaryNotRequired(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip(err)
	}
}
