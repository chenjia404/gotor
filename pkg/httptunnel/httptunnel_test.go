package httptunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func waitAddr(t *testing.T, s *Server) net.Addr {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if addr := s.Addr(); addr != nil {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("listener not ready")
	return nil
}

func TestHTTPConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peerCh := make(chan net.Conn, 1)
	var gotHost string
	var gotPort uint16
	s := New("127.0.0.1:0", func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		gotHost, gotPort = host, port
		up, down := net.Pipe()
		peerCh <- down
		return up, nil
	}, nil)

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx) }()
	addr := waitAddr(t, s)

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\nPING")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	peer := <-peerCh
	defer func() { _ = peer.Close() }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PING" {
		t.Fatalf("leftover %q", buf)
	}
	_, _ = peer.Write([]byte("ok"))
	got := make([]byte, 2)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	cancel()

	if gotHost != "example.test" || gotPort != 443 {
		t.Fatalf("got %s:%d", gotHost, gotPort)
	}
	if string(got) != "ok" {
		t.Fatalf("payload %q", got)
	}
}

func TestHTTPConnectDialFailsBefore200(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialed := false
	s := New("127.0.0.1:0", func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		dialed = true
		return nil, fmt.Errorf("stream rejected by exit")
	}, nil)
	go func() { _ = s.ListenAndServe(ctx) }()
	addr := waitAddr(t, s)
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	cancel()
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !dialed {
		t.Fatal("should dial before 200")
	}
}

func TestHTTPConnectRejectedByCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialed := false
	s := New("127.0.0.1:0", func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		dialed = true
		return nil, fmt.Errorf("should not dial")
	}, nil)
	s.SetCheck(func(host string, port uint16) (string, uint16, error) {
		return "", 0, fmt.Errorf("SafeSocks rejected IP literal")
	})

	go func() { _ = s.ListenAndServe(ctx) }()
	addr := waitAddr(t, s)
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	cancel()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if dialed {
		t.Fatal("rejected CONNECT must not dial")
	}
}

func TestHTTPConnectMethodNotAllowed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New("127.0.0.1:0", func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return nil, fmt.Errorf("no")
	}, nil)
	go func() { _ = s.ListenAndServe(ctx) }()
	addr := waitAddr(t, s)
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	cancel()
	if resp.StatusCode != 405 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	h, p, err := splitHostPortDefault("example.com", 443)
	if err != nil || h != "example.com" || p != 443 {
		t.Fatalf("%s %d %v", h, p, err)
	}
	h, p, err = splitHostPortDefault("example.com:9050", 443)
	if err != nil || h != "example.com" || p != 9050 {
		t.Fatalf("%s %d %v", h, p, err)
	}
	h, p, err = splitHostPortDefault("[::1]:443", 80)
	if err != nil || h != "::1" || p != 443 {
		t.Fatalf("%s %d %v", h, p, err)
	}
}

func TestStatusForDialError(t *testing.T) {
	if statusForDialError(context.DeadlineExceeded) != 504 {
		t.Fatal("timeout")
	}
	if statusForDialError(fmt.Errorf("SafeSocks rejected IP literal")) != 403 {
		t.Fatal("policy")
	}
	if statusForDialError(fmt.Errorf("stream rejected by exit")) != 502 {
		t.Fatal("exit")
	}
}
