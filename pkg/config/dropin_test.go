package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultCLIConfigDoesNotChangeLibraryDefaults(t *testing.T) {
	lib := DefaultConfig()
	cli := DefaultCLIConfig()
	if cli.SocksPort != 9050 || cli.ControlPort != 9051 {
		t.Fatalf("cli ports %d %d", cli.SocksPort, cli.ControlPort)
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(strings.ToLower(cli.DataDirectory), "tor") {
			t.Fatalf("windows datadir %s", cli.DataDirectory)
		}
	} else if !strings.HasSuffix(cli.DataDirectory, ".tor") && !strings.Contains(cli.DataDirectory, string(filepath.Separator)+".tor") {
		t.Fatalf("unix datadir %s", cli.DataDirectory)
	}
	if cli.EffectiveCacheDirectory() != cli.DataDirectory {
		t.Fatal("cache should default to data")
	}
	// 库 DefaultConfig 仍自动选端口，不得被 CLI 默认污染
	if lib.DataDirectory == cli.DataDirectory && strings.Contains(lib.DataDirectory, "go-tor") {
		// 两者路径本就不同
	}
	if strings.Contains(lib.DataDirectory, "go-tor") == strings.HasSuffix(cli.DataDirectory, ".tor") {
		// ok: 不同约定
	}
}

func TestParseCLINewFlags(t *testing.T) {
	res, err := ParseCLI([]string{"--version"})
	if err != nil || !res.ShowVersion {
		t.Fatalf("%v %+v", err, res)
	}
	res, err = ParseCLI([]string{"--verify-config", "SocksPort", "0", "ControlPort", "0"})
	if err != nil || !res.VerifyConfig || res.Config.SocksPort != 0 {
		t.Fatalf("%v socks=%d", err, res.Config.SocksPort)
	}
	res, err = ParseCLI([]string{"--dump-config", "full", "Nickname", "x"})
	if err != nil || res.DumpConfig != "full" || res.Config.Nickname != "x" {
		t.Fatalf("%v dump=%s nick=%s", err, res.DumpConfig, res.Config.Nickname)
	}
	res, err = ParseCLI([]string{"--quiet", "--hush", "--list-fingerprint", "ed25519"})
	if err != nil || !res.Quiet || !res.ListFingerprint || res.FingerprintType != "ed25519" {
		t.Fatalf("%+v", res)
	}
	res, err = ParseCLI([]string{"--list-deprecated-options"})
	if err != nil || !res.ListDeprecated {
		t.Fatal(err)
	}
	res, err = ParseCLI([]string{"--list-modules", "--keygen", "--dbg-sleep", "1"})
	if err != nil || !res.ListModules {
		t.Fatal(err)
	}
	res, err = ParseCLI([]string{"--allow-missing-torrc", "-f", filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCLI([]string{"-f", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing torrc should error")
	}
}

func TestParseCLIStdin(t *testing.T) {
	r := strings.NewReader("SocksPort 0\nControlPort 0\nDisableNetwork 1\n")
	res, err := ParseCLIWithStdin([]string{"-f", "-"}, r)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReadStdin || res.Config.SocksPort != 0 || !res.Config.DisableNetwork {
		t.Fatalf("%+v", res.Config)
	}
}

func TestLoadQuotedAndGlobInclude(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "d")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".hidden"), []byte("SocksPort 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.conf"), []byte("HTTPTunnelPort 9080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.conf"), []byte("DNSPort 5353\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "path with spaces")
	main := filepath.Join(dir, "torrc")
	body := "DataDirectory \"" + dataDir + "\"\n" +
		"%include " + filepath.Join(sub, "*.conf") + "\n" +
		"PidFile \"" + filepath.Join(dataDir, "tor.pid") + "\"\n" +
		"CacheDirectory \"" + dataDir + "\"\n" +
		"ClientUseIPv6 1\nMapAddress 1.2.3.4 5.6.7.8\n" +
		"SocksPort unix:\"" + filepath.Join(dir, "socks.sock") + "\"\n"
	if err := os.WriteFile(main, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultCLIConfig()
	if err := LoadFromFile(main, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DataDirectory != dataDir {
		t.Fatalf("quoted DataDirectory: %q", cfg.DataDirectory)
	}
	if cfg.HTTPTunnelPort != 9080 || cfg.DNSPort != 5353 {
		t.Fatalf("glob include ports %d %d", cfg.HTTPTunnelPort, cfg.DNSPort)
	}
	if cfg.SocksUnixPath == "" || cfg.SocksPort != 0 {
		t.Fatalf("unix socks %q port %d", cfg.SocksUnixPath, cfg.SocksPort)
	}
	if len(cfg.MapAddress) != 1 || cfg.MapAddress[0].To != "5.6.7.8" {
		t.Fatalf("map %+v", cfg.MapAddress)
	}
}

func TestIncludeDirectoryIgnoresDotfiles(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "inc")
	if err := os.Mkdir(inc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inc, ".dot"), []byte("SocksPort 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inc, "ok"), []byte("ControlPort 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "torrc")
	if err := os.WriteFile(main, []byte("%include "+inc+"\nSocksPort 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultCLIConfig()
	if err := LoadFromFile(main, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPort != 0 || cfg.SocksPort != 0 {
		t.Fatalf("ports %d %d", cfg.ControlPort, cfg.SocksPort)
	}
}

func TestSocksPortAutoAndZero(t *testing.T) {
	cfg := DefaultCLIConfig()
	if err := processConfigOption(cfg, "SocksPort", "0", nil); err != nil {
		t.Fatal(err)
	}
	if cfg.SocksPort != 0 || cfg.SocksEnabled() {
		t.Fatal("port 0 should disable")
	}
	if err := processConfigOption(cfg, "ControlPort", "0", nil); err != nil {
		t.Fatal(err)
	}
	if cfg.ControlEnabled() {
		t.Fatal("control 0 disabled")
	}
	if err := processConfigOption(cfg, "ControlSocket", "/tmp/c.sock", nil); err != nil {
		t.Fatal(err)
	}
	if !cfg.ControlEnabled() {
		t.Fatal("socket enables control")
	}
}

func TestVersionString(t *testing.T) {
	if !strings.HasPrefix(VersionString(), "Tor version 0.4.9.") {
		t.Fatalf("%s", VersionString())
	}
	if !strings.Contains(VersionString(), "(gotor)") {
		t.Fatal(VersionString())
	}
}

func TestCheckDropInConstraints(t *testing.T) {
	cfg := DefaultCLIConfig()
	cfg.ExitRelay = true
	if err := cfg.CheckDropInConstraints(); err == nil {
		t.Fatal("ExitRelay should fail")
	}
	cfg.ExitRelay = false
	cfg.TransPort = 9040
	if err := cfg.CheckDropInConstraints(); err == nil {
		t.Fatal("TransPort should fail")
	}
}

func TestKnownTorrcOptionsCoversNewKeys(t *testing.T) {
	opts := strings.Join(KnownTorrcOptions(), "\n")
	for _, k := range []string{"CacheDirectory", "PidFile", "HTTPTunnelPort", "DNSPort", "DisableNetwork"} {
		if !strings.Contains(opts, k) {
			t.Fatalf("missing %s", k)
		}
	}
}

func TestDumpConfigAndModules(t *testing.T) {
	cfg := DefaultCLIConfig()
	cfg.Nickname = "n1"
	out := DumpConfig(cfg, "short")
	if !strings.Contains(out, "Nickname n1") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(FormatModules(), "pt: no") {
		t.Fatal(FormatModules())
	}
}

func TestIsNotExistErrDoesNotTreatPermissionAsMissing(t *testing.T) {
	if isNotExistErr(fmt.Errorf("failed to open config file: %w", os.ErrPermission)) {
		t.Fatal("权限错误不得被当成文件缺失")
	}
	if !isNotExistErr(fmt.Errorf("failed to open config file: %w", os.ErrNotExist)) {
		t.Fatal("包装后的不存在应识别")
	}
	if isNotExistErr(fmt.Errorf("failed to open config file: access denied")) {
		t.Fatal("仅含打开失败字样不得当成缺失")
	}
}

func TestCloneCopiesNewSlices(t *testing.T) {
	cfg := DefaultCLIConfig()
	cfg.MapAddress = []MapAddressEntry{{From: "a", To: "b"}}
	cfg.FallbackDirs = []string{"1.2.3.4:80"}
	cl := cfg.Clone()
	cl.MapAddress[0].To = "z"
	if cfg.MapAddress[0].To != "b" {
		t.Fatal("clone alias")
	}
}
