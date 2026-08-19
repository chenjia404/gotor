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

func TestHTTPConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gotHost string
	var gotPort uint16
	s := New("127.0.0.1:0", func(ctx context.Context, conn net.Conn, host string, port uint16) error {
		gotHost, gotPort = host, port
		_, _ = conn.Write([]byte("ok"))
		return nil
	}, nil)

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	var addr net.Addr
	for time.Now().Before(deadline) {
		addr = s.Addr()
		if addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("listener not ready")
	}

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
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	cancel()

	if gotHost != "example.test" || gotPort != 443 {
		t.Fatalf("got %s:%d", gotHost, gotPort)
	}
}

func TestHTTPConnectRejectedByCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamed := false
	s := New("127.0.0.1:0", func(ctx context.Context, conn net.Conn, host string, port uint16) error {
		streamed = true
		return nil
	}, nil)
	s.SetCheck(func(host string, port uint16) (string, uint16, error) {
		return "", 0, fmt.Errorf("SafeSocks rejected IP literal")
	})

	go func() { _ = s.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	var addr net.Addr
	for time.Now().Before(deadline) {
		addr = s.Addr()
		if addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("listener not ready")
	}
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
	if streamed {
		t.Fatal("rejected CONNECT must not stream")
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
}
