package socks

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/onion"
)

// Dial 经 Tor 打开 host:port。成功返回时已收到 RELAY_CONNECTED。
// HTTPTunnelPort 与 SOCKS CONNECT 共用。禁止本机 DNS。
func (s *Server) Dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if s == nil {
		return nil, fmt.Errorf("socks server is nil")
	}
	if port < 1 {
		return nil, fmt.Errorf("invalid port")
	}
	if onion.IsOnionAddress(host) {
		return s.dialOnion(ctx, host, port)
	}
	return s.dialExit(ctx, host, port)
}

func (s *Server) dialOnion(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if s.onionClient == nil || s.circuitMgr == nil {
		return nil, fmt.Errorf("onion client not configured")
	}
	addr, err := onion.ParseAddress(host)
	if err != nil {
		return nil, fmt.Errorf("invalid onion address: %w", err)
	}
	s.logger.Info("HTTP/SOCKS onion dial", "address", host, "port", port)
	circuitID, err := s.onionClient.ConnectToOnionService(ctx, addr)
	if err != nil {
		return nil, err
	}
	circ, err := s.circuitMgr.GetCircuit(circuitID)
	if err != nil {
		return nil, fmt.Errorf("rendezvous circuit %d: %w", circuitID, err)
	}
	sc, err := circuit.OpenStreamConn(ctx, circ, host, port, nil)
	if err != nil {
		return nil, fmt.Errorf("RELAY_BEGIN to onion: %w", err)
	}
	return sc, nil
}

func (s *Server) dialExit(ctx context.Context, host string, port uint16) (net.Conn, error) {
	s.mu.Lock()
	circuitPool := s.circuitPool
	circuitForExit := s.circuitForExit
	s.mu.Unlock()
	if circuitPool == nil {
		return nil, fmt.Errorf("no circuit pool available")
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	destIP := net.ParseIP(host)
	allowExit := func(c *circuit.Circuit) bool {
		return c.AllowsExit(destIP, int(port))
	}
	circ, err := circuitPool.GetIf(timeoutCtx, nil, allowExit)
	if err != nil {
		return nil, err
	}
	circ, err = replaceIfExitRejected(timeoutCtx, circ, destIP, int(port), circuitPool, circuitForExit, nil)
	if err != nil {
		return nil, err
	}
	sc, err := circuit.OpenStreamConn(timeoutCtx, circ, host, port, func() {
		circuitPool.Put(circ)
	})
	if err != nil {
		circuitPool.Put(circ)
		return nil, err
	}
	return sc, nil
}
