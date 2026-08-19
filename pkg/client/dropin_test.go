package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestClientLockAndDisabledPorts(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultCLIConfig()
	cfg.DataDirectory = dir
	cfg.CacheDirectory = dir
	cfg.SocksPort = 0
	cfg.ControlPort = 0
	cfg.DisableNetwork = true
	cfg.PidFile = filepath.Join(dir, "tor.pid")
	cfg.LogLevel = "error"

	c, err := New(cfg, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := datadir.TryLock(dir); err == nil {
		t.Fatal("data dir should be locked after Start")
	}
	if _, err := os.Stat(cfg.PidFile); err != nil {
		t.Fatalf("pidfile: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.PidFile); !os.IsNotExist(err) {
		t.Fatal("pidfile should be removed")
	}
	l, err := datadir.TryLock(dir)
	if err != nil {
		t.Fatalf("lock should be released: %v", err)
	}
	_ = l.Unlock()
}

func TestMapAddressToMapLowercases(t *testing.T) {
	m := mapAddressToMap([]config.MapAddressEntry{{From: "Example.COM", To: "10.0.0.1"}})
	if m["example.com"] != "10.0.0.1" {
		t.Fatalf("%v", m)
	}
}

func TestRewriteAndCheckTarget(t *testing.T) {
	c := &Client{config: config.DefaultCLIConfig(), logger: logger.NewDefault()}
	c.config.SafeSocks = true
	if _, _, err := c.rewriteAndCheckTarget("1.2.3.4", 443); err == nil {
		t.Fatal("SafeSocks 应拒绝 IP 字面量")
	}
	if h, p, err := c.rewriteAndCheckTarget("example.com", 443); err != nil || h != "example.com" || p != 443 {
		t.Fatalf("%s %d %v", h, p, err)
	}
	c.config.SafeSocks = false
	c.config.ClientRejectInternalAddresses = true
	if _, _, err := c.rewriteAndCheckTarget("192.168.1.1", 80); err == nil {
		t.Fatal("应拒绝内网")
	}
	c.config.ClientRejectInternalAddresses = false
	c.config.MapAddress = []config.MapAddressEntry{{From: "Foo.Example", To: "bar.example"}}
	if h, _, err := c.rewriteAndCheckTarget("FOO.EXAMPLE", 80); err != nil || h != "bar.example" {
		t.Fatalf("MapAddress 大小写 %s %v", h, err)
	}
}
