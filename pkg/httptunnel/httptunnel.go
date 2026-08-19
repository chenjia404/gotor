// Package httptunnel 实现 C Tor HTTPTunnelPort：HTTP CONNECT，经电路转发。
package httptunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// StreamFunc 把已建立的客户端连接接到目标 host:port（经 Tor 电路）。
// 实现方禁止对本机做 DNS。
type StreamFunc func(ctx context.Context, conn net.Conn, host string, port uint16) error

// CheckFunc 在回复 200 之前改写或拒绝目标（MapAddress / SafeSocks 等）。
type CheckFunc func(host string, port uint16) (string, uint16, error)

// Server 是 HTTP CONNECT 隧道。
type Server struct {
	network string
	address string
	stream  StreamFunc
	check   CheckFunc
	logger  *logger.Logger
	ln      net.Listener
	mu      sync.Mutex
}

// SetCheck 设置 CONNECT 目标策略检查。
func (s *Server) SetCheck(fn CheckFunc) {
	s.check = fn
}

func New(addr string, stream StreamFunc, log *logger.Logger) *Server {
	if log == nil {
		log = logger.NewDefault()
	}
	return &Server{
		network: "tcp",
		address: addr,
		stream:  stream,
		logger:  log.Component("httptunnel"),
	}
}

// SetUnix 改为 unix socket 监听。
func (s *Server) SetUnix(path string) {
	s.network = "unix"
	s.address = path
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.stream == nil {
		return fmt.Errorf("httptunnel: stream handler required")
	}
	if s.network == "unix" {
		if err := datadir.PrepareUnixSocket(s.address); err != nil {
			return err
		}
	}
	ln, err := net.Listen(s.network, s.address)
	if err != nil {
		return err
	}
	if s.network == "unix" {
		if err := os.Chmod(s.address, 0o600); err != nil {
			_ = ln.Close()
			return fmt.Errorf("chmod httptunnel unix socket: %w", err)
		}
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.logger.Info("HTTP tunnel listening", "network", s.network, "addr", s.address)

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		s.logger.Debug("httptunnel read request", "error", err)
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		return
	}
	host, port, err := splitHostPortDefault(req.Host, 443)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}
	if s.check != nil {
		host, port, err = s.check(host, port)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
			s.logger.Debug("httptunnel rejected target", "host", host, "error", err)
			return
		}
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	if err := s.stream(ctx, conn, host, port); err != nil {
		s.logger.Debug("httptunnel stream", "host", host, "error", err)
	}
}

func splitHostPortDefault(hostport string, def uint16) (string, uint16, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if !strings.Contains(hostport, ":") {
		return hostport, def, nil
	}
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("bad port")
	}
	return h, uint16(n), nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	err := ln.Close()
	if s.network == "unix" {
		_ = os.Remove(s.address)
	}
	return err
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}
