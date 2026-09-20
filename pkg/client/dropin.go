package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/dnsport"
	"github.com/opd-ai/go-tor/pkg/httptunnel"
	"github.com/opd-ai/go-tor/pkg/path"
	"github.com/opd-ai/go-tor/pkg/socks"
)

func mapAddressToMap(entries []config.MapAddressEntry) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.From != "" && e.To != "" {
			// 与 SOCKS applyAddressMap 一致：主机名按小写查找（C Tor 大小写不敏感）
			m[strings.ToLower(e.From)] = e.To
		}
	}
	return m
}

func (c *Client) startExtraListeners(ctx context.Context) {
	if c.config.HTTPTunnelEnabled() {
		ht := httptunnel.New("127.0.0.1:0", c.dialThroughCircuit, c.logger)
		if c.config.HTTPTunnelUnixPath != "" {
			ht.SetUnix(c.config.HTTPTunnelUnixPath)
		} else {
			host := c.config.HTTPTunnelListenAddr
			if host == "" {
				host = "127.0.0.1"
			}
			addr := net.JoinHostPort(host, strconv.Itoa(c.config.HTTPTunnelPort))
			c.warnIfNonLoopback("HTTPTunnelPort", host, addr)
			ht = httptunnel.New(addr, c.dialThroughCircuit, c.logger)
		}
		ht.SetCheck(c.checkHTTPTunnelTarget)
		c.httpTunnel = ht
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if err := c.httpTunnel.ListenAndServe(ctx); err != nil {
				c.logger.Error("HTTPTunnelPort error", "error", err)
			}
		}()
	}
	if c.config.DNSPort > 0 {
		host := c.config.DNSPortListenAddr
		if host == "" {
			host = "127.0.0.1"
		}
		addr := net.JoinHostPort(host, strconv.Itoa(c.config.DNSPort))
		c.warnIfNonLoopback("DNSPort", host, addr)
		c.dnsServer = dnsport.New(addr, c.resolveThroughCircuit, c.logger)
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if err := c.dnsServer.ListenAndServe(ctx); err != nil {
				c.logger.Error("DNSPort error", "error", err)
			}
		}()
	}
}

func (c *Client) acquireCircuit(ctx context.Context, host string, port uint16) (*circuit.Circuit, func(), error) {
	if c.config.DisableNetwork {
		return nil, nil, fmt.Errorf("DisableNetwork is set")
	}
	if c.circuitPool != nil {
		circ, err := c.circuitPool.Get(ctx)
		if err != nil {
			return nil, nil, err
		}
		return circ, func() { c.circuitPool.Put(circ) }, nil
	}
	circ, err := c.buildCircuitForTarget(ctx, path.ExitTarget{Port: int(port)})
	if err != nil {
		return nil, nil, err
	}
	return circ, func() {
		_ = c.circuitMgr.CloseCircuit(circ.ID)
	}, nil
}

func (c *Client) warnIfNonLoopback(name, host, addr string) {
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		c.logger.Warn(name+" 绑定非回环地址，任意可达客户端可经本进程出网或消耗电路", "addr", addr)
	}
}

// checkHTTPTunnelTarget 在 HTTP CONNECT 写 200 之前对齐 SOCKS 的 MapAddress / SafeSocks / 内网拒绝。
func (c *Client) checkHTTPTunnelTarget(host string, port uint16) (string, uint16, error) {
	return c.rewriteAndCheckTarget(host, port)
}

func (c *Client) rewriteAndCheckTarget(host string, port uint16) (string, uint16, error) {
	mapped := socks.ApplyAddressMap(mapAddressToMap(c.config.MapAddress), net.JoinHostPort(host, strconv.Itoa(int(port))))
	if mapped != "" {
		if h, p, err := net.SplitHostPort(mapped); err == nil {
			host = h
			if n, e := strconv.Atoi(p); e == nil && n > 0 && n <= 65535 {
				port = uint16(n)
			}
		}
	}
	destIP := net.ParseIP(host)
	if c.config.TestSocks && destIP != nil {
		c.logger.Info("TestSocks: destination is an IP literal", "host", host)
	}
	if c.config.SafeSocks && destIP != nil {
		return "", 0, fmt.Errorf("SafeSocks rejected IP literal")
	}
	if c.config.ClientRejectInternalAddresses && destIP != nil && socks.IsInternalIP(destIP) {
		return "", 0, fmt.Errorf("ClientRejectInternalAddresses")
	}
	return host, port, nil
}

func (c *Client) dialThroughCircuit(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if c.config != nil && c.config.DisableNetwork {
		return nil, fmt.Errorf("DisableNetwork is set")
	}
	if c.socksServer == nil {
		return nil, fmt.Errorf("HTTP CONNECT 需要 SOCKS 电路栈")
	}
	return c.socksServer.Dial(ctx, host, port)
}

func (c *Client) resolveThroughCircuit(ctx context.Context, name string) ([]net.IP, uint32, error) {
	circ, release, err := c.acquireCircuit(ctx, name, 53)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	res, err := circ.ResolveHostname(ctx, name)
	if err != nil {
		return nil, 0, err
	}
	return res.Addresses, res.TTL, nil
}
