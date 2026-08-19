package mobile

import (
	"testing"
)

func TestValidateStartArgs(t *testing.T) {
	t.Parallel()

	if err := validateStartArgs("", 9050); err == nil {
		t.Fatal("空 dataDir 应报错")
	}
	if err := validateStartArgs("   ", 9050); err == nil {
		t.Fatal("空白 dataDir 应报错")
	}
	if err := validateStartArgs(t.TempDir(), 0); err == nil {
		t.Fatal("socksPort=0 应报错")
	}
	if err := validateStartArgs(t.TempDir(), -1); err == nil {
		t.Fatal("负 socksPort 应报错")
	}
	if err := validateStartArgs(t.TempDir(), 65536); err == nil {
		t.Fatal("socksPort>65535 应报错")
	}
	if err := validateStartArgs(t.TempDir(), 9050); err != nil {
		t.Fatalf("合法参数不应报错: %v", err)
	}
}

func TestBuildMobileConfigConstraints(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := buildMobileConfig(dir, 19050)

	if cfg.DataDirectory != dir {
		t.Fatalf("DataDirectory=%q, want %q", cfg.DataDirectory, dir)
	}
	if cfg.SocksPort != 19050 {
		t.Fatalf("SocksPort=%d, want 19050", cfg.SocksPort)
	}
	if cfg.SocksListenAddr != "127.0.0.1" {
		t.Fatalf("SocksListenAddr=%q, 必须为 127.0.0.1", cfg.SocksListenAddr)
	}
	if cfg.ControlPort != 0 {
		t.Fatalf("ControlPort 应关闭, got %d", cfg.ControlPort)
	}
	if cfg.MetricsPort != 0 || cfg.EnableMetrics {
		t.Fatal("Metrics 应关闭")
	}
	if cfg.ORPort != 0 {
		t.Fatalf("中继应关闭: ORPort=%d", cfg.ORPort)
	}
	if len(cfg.OnionServices) != 0 {
		t.Fatalf("洋葱托管应关闭, got %d", len(cfg.OnionServices))
	}
	if cfg.PublishServerDescriptor || cfg.ExitRelay {
		t.Fatal("不应发布描述符或作为出口")
	}
	if cfg.CircuitPoolMinSize != 1 || cfg.CircuitPoolMaxSize != 3 {
		t.Fatalf("电路池应为 min=1 max=3, got %d/%d", cfg.CircuitPoolMinSize, cfg.CircuitPoolMaxSize)
	}
	if cfg.IsolationLevel != "destination" || !cfg.IsolateDestinations {
		t.Fatalf("应启用目的地隔离, level=%q isolate=%v", cfg.IsolationLevel, cfg.IsolateDestinations)
	}
	if cfg.EnableProfiling || cfg.EnableTracing {
		t.Fatal("Profiling/Tracing 应关闭")
	}
	if err := enforceLoopbackSocks(cfg); err != nil {
		t.Fatalf("默认配置应通过回环检查: %v", err)
	}
}

func TestEnforceLoopbackSocks(t *testing.T) {
	t.Parallel()

	if err := enforceLoopbackSocks(nil); err == nil {
		t.Fatal("空配置应报错")
	}

	cfg := buildMobileConfig(t.TempDir(), 9050)
	cfg.SocksListenAddr = "0.0.0.0"
	if err := enforceLoopbackSocks(cfg); err == nil {
		t.Fatal("0.0.0.0 必须被拒绝")
	}
	cfg.SocksListenAddr = "::"
	if err := enforceLoopbackSocks(cfg); err == nil {
		t.Fatal("IPv6 通配必须被拒绝")
	}
	cfg.SocksListenAddr = "127.0.0.1"
	if err := enforceLoopbackSocks(cfg); err != nil {
		t.Fatalf("127.0.0.1 应通过: %v", err)
	}
}

func TestIsLoopbackBind(t *testing.T) {
	t.Parallel()

	if !isLoopbackBind("127.0.0.1") || !isLoopbackBind("localhost") {
		t.Fatal("本机地址应视为回环")
	}
	for _, addr := range []string{"0.0.0.0", "::", "192.168.1.1", ""} {
		if isLoopbackBind(addr) {
			t.Fatalf("%q 不应视为安全绑定", addr)
		}
	}
}
