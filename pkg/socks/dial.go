package socks

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/onion"
	"github.com/opd-ai/go-tor/pkg/stream"
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
	s.trackDialStream(sc, circ.ID, host, port)
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
	s.trackDialStream(sc, circ.ID, host, port)
	return sc, nil
}

// trackDialStream 把 HTTP CONNECT / Dial 成功的流登记进 streamMgr，供 GETINFO stream-status。
func (s *Server) trackDialStream(sc *circuit.StreamConn, circuitID uint32, host string, port uint16) {
	if s == nil || sc == nil || s.streamMgr == nil {
		return
	}
	sid := sc.StreamID()
	if sid == 0 {
		return
	}
	strm, err := s.streamMgr.CreateStreamWithID(sid, circuitID, host, port)
	if err != nil {
		s.logger.Debug("stream-status 未登记 Dial 流", "error", err)
		return
	}
	strm.SetState(stream.StateConnected)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	s.publishStream(uint32(sid), circuitID, "SUCCEEDED", target)
	sc.AfterClose(func() {
		_ = s.streamMgr.RemoveStream(circuitID, sid)
		s.publishStream(uint32(sid), circuitID, "CLOSED", target)
	})
}

// ListStreamSnapshots 返回 SOCKS / HTTP CONNECT 当前未关闭的流。
func (s *Server) ListStreamSnapshots() []stream.StreamSnapshot {
	if s == nil || s.streamMgr == nil {
		return nil
	}
	return s.streamMgr.ListSnapshots()
}
