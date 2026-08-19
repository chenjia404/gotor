package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

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
	if c.config.HTTPTunnelPort > 0 {
		host := c.config.HTTPTunnelListenAddr
		if host == "" {
			host = "127.0.0.1"
		}
		addr := net.JoinHostPort(host, strconv.Itoa(c.config.HTTPTunnelPort))
		c.warnIfNonLoopback("HTTPTunnelPort", host, addr)
		c.httpTunnel = httptunnel.New(addr, c.streamThroughCircuit, c.logger)
		c.httpTunnel.SetCheck(c.checkHTTPTunnelTarget)
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

func (c *Client) streamThroughCircuit(ctx context.Context, conn net.Conn, host string, port uint16) error {
	host, port, err := c.rewriteAndCheckTarget(host, port)
	if err != nil {
		return err
	}
	circ, release, err := c.acquireCircuit(ctx, host, port)
	if err != nil {
		return err
	}
	defer release()

	streamID, err := circ.AllocateStreamID()
	if err != nil {
		return err
	}
	defer circ.ReleaseStreamID(streamID)
	if err := circ.OpenStream(ctx, streamID, host, port); err != nil {
		return err
	}
	relayConnThroughCircuit(ctx, conn, circ, streamID)
	return nil
}

func relayConnThroughCircuit(ctx context.Context, conn net.Conn, circ *circuit.Circuit, streamID uint16) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, circ.RelayDataMax())
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := circ.WriteToStream(streamID, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				_ = circ.EndStream(streamID, 6)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			data, err := circ.ReadFromStream(ctx, streamID)
			if err != nil {
				_ = conn.Close()
				return
			}
			if _, err := conn.Write(data); err != nil {
				_ = circ.EndStream(streamID, 6)
				return
			}
		}
	}()
	wg.Wait()
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
