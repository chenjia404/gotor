package mobile

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/client"
)

func TestWaitUntilReadyNilClient(t *testing.T) {
	t.Parallel()
	if err := waitUntilReady(nil, context.Background(), time.Millisecond); err == nil {
		t.Fatal("空客户端应报错")
	}
}

func TestWaitUntilReadyTimeoutNoNetwork(t *testing.T) {
	t.Parallel()

	cfg := buildMobileConfig(t.TempDir(), 19054)
	c, err := client.New(cfg, newMobileLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := waitUntilReady(c, ctx, 200*time.Millisecond); err == nil {
		t.Fatal("未建电路时应超时或取消")
	}
}

func TestWaitSocksLoopbackRejectsWildcard(t *testing.T) {
	t.Parallel()
	if err := waitSocksLoopback(context.Background(), "0.0.0.0:9050", time.Millisecond); err == nil {
		t.Fatal("必须拒绝探测 0.0.0.0")
	}
}

func TestWaitSocksLoopbackAcceptsLocalListener(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := waitSocksLoopback(ctx, ln.Addr().String(), 2*time.Second); err != nil {
		t.Fatalf("本机监听应探测成功: %v", err)
	}
}

func TestWaitSocksLoopbackTimeout(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := waitSocksLoopback(ctx, addr, 250*time.Millisecond); err == nil {
		t.Fatal("无监听时应超时")
	}
}
