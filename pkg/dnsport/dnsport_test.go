package dnsport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseAndBuildDNS(t *testing.T) {
	q := append([]byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, encodeName("example.test")...)
	q = append(q, 0x00, 0x01, 0x00, 0x01)
	id, name, qtype, ok := parseDNSQuery(q)
	if !ok || id != 0x1234 || name != "example.test" || qtype != 1 {
		t.Fatalf("%v %q %d %v", id, name, qtype, ok)
	}
	resp := buildDNSResponse(id, name, qtype, 0, []dnsRR{{
		Name: name, Type: 1, TTL: 60, Data: net.IPv4(1, 2, 3, 4).To4(),
	}})
	if len(resp) < 32 {
		t.Fatalf("short response %d", len(resp))
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatal("id mismatch")
	}
}

func TestDNSPortResolveNoLocalDNS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	called := make(chan string, 1)
	s := New("127.0.0.1:0", func(ctx context.Context, name string) ([]net.IP, uint32, error) {
		called <- name
		return []net.IP{net.IPv4(5, 6, 7, 8)}, 30, nil
	}, nil)

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx) }()

	var addr net.Addr
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		addr = s.LocalAddr()
		if addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("udp not ready")
	}

	c, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := append([]byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, encodeName("tor.test")...)
	q = append(q, 0x00, 0x01, 0x00, 0x01)
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("short %d", n)
	}
	select {
	case name := <-called:
		if name != "tor.test" {
			t.Fatalf("resolved %q", name)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver not called — must not use local DNS")
	}
	cancel()
}
