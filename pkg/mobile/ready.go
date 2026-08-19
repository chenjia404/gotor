package mobile

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/opd-ai/go-tor/pkg/client"
)

const (
	readyPollInterval = 100 * time.Millisecond
	readyWaitTimeout  = 90 * time.Second
	socksWaitTimeout  = 5 * time.Second
)

// waitUntilReady 等到客户端有可用电路，或 context / 超时失败。
func waitUntilReady(c *client.Client, ctx context.Context, timeout time.Duration) error {
	if c == nil {
		return fmt.Errorf("客户端为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = readyWaitTimeout
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(readyPollInterval)
	defer ticker.Stop()

	if clientIsReady(c) {
		return nil
	}
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("等待电路就绪超时")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if clientIsReady(c) {
				return nil
			}
		}
	}
}

// waitSocksLoopback 确认本机 SOCKS 已开始接受连接（只拨 127.0.0.1，不连外网）。
func waitSocksLoopback(ctx context.Context, addr string, timeout time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = socksWaitTimeout
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("非法 SOCKS 地址: %w", err)
	}
	if !isLoopbackBind(host) {
		return fmt.Errorf("拒绝探测非回环地址 %q", host)
	}

	deadline := time.Now().Add(timeout)
	dialer := net.Dialer{Timeout: readyPollInterval}
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("等待 SOCKS 监听超时")
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readyPollInterval):
		}
	}
}
