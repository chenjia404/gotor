// Package httptunnel 实现 C Tor HTTPTunnelPort：HTTP CONNECT，经电路转发。
// 对齐 C Tor：只接受 CONNECT；RELAY_CONNECTED 成功后才回 200；失败映射 403/502/504。
// 不实现 Arti prop 365 扩展头（P2）。
package httptunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// DialFunc 在回复 200 之前建立电路流。实现方禁止对本机做 DNS。
type DialFunc func(ctx context.Context, host string, port uint16) (net.Conn, error)

// CheckFunc 在拨号之前改写或拒绝目标（MapAddress / SafeSocks 等）。
type CheckFunc func(host string, port uint16) (string, uint16, error)

const connectedReply = "HTTP/1.0 200 Connection established\r\n\r\n"

// Server 是 HTTP CONNECT 隧道。
type Server struct {
	network string
	address string
	dial    DialFunc
	check   CheckFunc
	logger  *logger.Logger
	ln      net.Listener
	mu      sync.Mutex
}

// SetCheck 设置 CONNECT 目标策略检查。
func (s *Server) SetCheck(fn CheckFunc) {
	s.check = fn
}

func New(addr string, dial DialFunc, log *logger.Logger) *Server {
	if log == nil {
		log = logger.NewDefault()
	}
	return &Server{
		network: "tcp",
		address: addr,
		dial:    dial,
		logger:  log.Component("httptunnel"),
	}
}

// SetUnix 改为 unix socket 监听。
func (s *Server) SetUnix(path string) {
	s.network = "unix"
	s.address = path
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.dial == nil {
		return fmt.Errorf("httptunnel: dial handler required")
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
	if req.Body != nil {
		_ = req.Body.Close()
	}
	if req.Method != http.MethodConnect {
		writeStatus(conn, 405)
		return
	}
	target := connectAuthority(req)
	host, port, err := splitHostPortDefault(target, 443)
	if err != nil {
		writeStatus(conn, 400)
		return
	}
	if s.check != nil {
		host, port, err = s.check(host, port)
		if err != nil {
			s.logger.Info("HTTP CONNECT rejected", "host", host, "error", err)
			writeStatus(conn, 403)
			return
		}
	}
	s.logger.Info("HTTP CONNECT", "host", host, "port", port)
	dialCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	remote, err := s.dial(dialCtx, host, port)
	cancel()
	if err != nil {
		s.logger.Info("HTTP CONNECT failed", "host", host, "port", port, "error", err)
		writeStatus(conn, statusForDialError(err))
		return
	}
	defer func() { _ = remote.Close() }()
	if _, err := io.WriteString(conn, connectedReply); err != nil {
		return
	}
	s.logger.Info("HTTP CONNECT established", "host", host, "port", port)
	client := &prefixConn{Conn: conn, r: io.MultiReader(br, conn)}
	relayBidir(client, remote)
}

func connectAuthority(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	if req.Host != "" {
		return req.Host
	}
	return req.RequestURI
}

func statusForDialError(err error) int {
	if err == nil {
		return 200
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return 504
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "safesocks"),
		strings.Contains(msg, "clientrejectinternal"),
		strings.Contains(msg, "forbidden"),
		strings.Contains(msg, "disablenetwork"),
		strings.Contains(msg, "not allowed"):
		return 403
	default:
		return 502
	}
}

func writeStatus(w io.Writer, code int) {
	reason := http.StatusText(code)
	if reason == "" {
		reason = "Error"
	}
	_, _ = fmt.Fprintf(w, "HTTP/1.0 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason)
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

func relayBidir(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		_ = closeWrite(b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		_ = closeWrite(a)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) error {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		return x.CloseWrite()
	}
	return c.Close()
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
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
