package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/connection"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// bufferedPipe 给握手测试用：net.Pipe 无缓冲，双方同时写 CERTS/NETINFO 会堵死。
func bufferedPipe() (net.Conn, net.Conn) {
	ab := make(chan []byte, 64)
	ba := make(chan []byte, 64)
	return newBufConn(ba, ab), newBufConn(ab, ba)
}

type bufConn struct {
	in     <-chan []byte
	out    chan<- []byte
	remain []byte
	closed chan struct{}
	once   sync.Once
}

func newBufConn(in <-chan []byte, out chan<- []byte) *bufConn {
	return &bufConn{in: in, out: out, closed: make(chan struct{})}
}

func (c *bufConn) Read(p []byte) (int, error) {
	if len(c.remain) == 0 {
		select {
		case <-c.closed:
			return 0, io.EOF
		case b, ok := <-c.in:
			if !ok {
				return 0, io.EOF
			}
			c.remain = b
		}
	}
	n := copy(p, c.remain)
	c.remain = c.remain[n:]
	return n, nil
}

func (c *bufConn) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.out <- cp:
		return len(p), nil
	}
}

func (c *bufConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *bufConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *bufConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}
func (c *bufConn) SetDeadline(time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error { return nil }

func TestNewOutboundCircID_MSB(t *testing.T) {
	seen := make(map[uint32]struct{}, 64)
	for i := 0; i < 64; i++ {
		id := newOutboundCircID()
		if id&0x80000000 == 0 {
			t.Fatalf("CircID %#x 未置 MSB（link v4+ 发起方必须为 1）", id)
		}
		if id == 0 || id == 0x80000000 {
			t.Fatalf("非法 CircID %#x", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) < 32 {
		t.Fatalf("CircID 随机性不足: unique=%d", len(seen))
	}
}

func TestIdentitiesFromLinkSpecs(t *testing.T) {
	rsa := bytes.Repeat([]byte{0xAB}, 20)
	ed := bytes.Repeat([]byte{0xCD}, 32)
	id := identitiesFromLinkSpecs([]LinkSpecifier{
		{Type: 0, Data: []byte{127, 0, 0, 1, 0x23, 0x8C}},
		{Type: 2, Data: rsa},
		{Type: 3, Data: ed},
	})
	if !id.hasIdentity() {
		t.Fatal("expected identity")
	}
	wantFP := fmt.Sprintf("%X", rsa)
	if id.rsaFingerprint != wantFP {
		t.Fatalf("fingerprint=%s want %s", id.rsaFingerprint, wantFP)
	}
	if !bytes.Equal(id.ed25519, ed) {
		t.Fatal("ed25519 mismatch")
	}
	if identitiesFromLinkSpecs(nil).hasIdentity() {
		t.Fatal("empty specs should have no identity")
	}
	if identitiesFromLinkSpecs([]LinkSpecifier{{Type: 2, Data: []byte{1, 2}}}).hasIdentity() {
		t.Fatal("short type-2 should be ignored")
	}
}

func TestHandleExtend2_MissingIdentity(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	h := NewExtensionHandler(keys, NewCircuitHandler(keys, logger.NewDefault()), logger.NewDefault())
	data := []byte{
		1, 0, 6, 127, 0, 0, 1, 0x1F, 0x90,
		0x00, 0x02, 0x00, 0x04, 0, 1, 2, 3,
	}
	err = h.HandleExtend2(context.Background(), 1, &cell.RelayCell{
		Command: cell.RelayExtend2,
		Data:    data,
	}, nil)
	if err == nil {
		t.Fatal("expected error without identity specifier")
	}
}

func onionEncryptTowardHop(t *testing.T, km, plain []byte) []byte {
	t.Helper()
	client, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	enc := append([]byte(nil), plain...)
	client.fwdCipher.XORKeyStream(enc, enc)
	return enc
}

func clientDecryptFromHop(t *testing.T, km, enc []byte) []byte {
	t.Helper()
	client, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), enc...)
	client.bwdCipher.XORKeyStream(out, out)
	return out
}

func TestMiddleHopPeelForwardAndReturn(t *testing.T) {
	log := logger.NewDefault()
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	ch := NewCircuitHandler(keys, log)
	km := make([]byte, 72)
	for i := range km {
		km[i] = byte(i + 1)
	}
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	ch.mu.Lock()
	ch.circuits[100] = &ServerCircuit{
		CircuitID:    100,
		Created:      time.Now(),
		LastActivity: time.Now(),
		KeyMaterial:  km,
		crypto:       cc,
	}
	ch.mu.Unlock()

	nextHop := newTestMockConn()
	clientConn := newTestMockConn()
	if err := ch.forwarder.RegisterExtendedCircuit(100, 0x80000002, "192.0.2.1:9001", nextHop); err != nil {
		t.Fatal(err)
	}
	ch.forwarder.extendedMu.Lock()
	ch.forwarder.extended[100].ClientConn = clientConn
	ext := ch.forwarder.extended[100]
	ch.forwarder.extendedMu.Unlock()

	inner := make([]byte, 509)
	inner[0] = cell.RelayData
	inner[1] = 0x01 // recognized ≠ 0：本跳只剥层转发
	inner[11] = 0xAB
	enc := onionEncryptTowardHop(t, km, inner)

	c := &cell.Cell{CircID: 100, Command: cell.CmdRelay, Payload: enc}
	if err := ch.forwarder.ForwardRelayCell(context.Background(), true, 100, c, clientConn); err != nil {
		t.Fatal(err)
	}
	fwd, err := cell.DecodeCell(bytes.NewReader(nextHop.writeData))
	if err != nil {
		t.Fatal(err)
	}
	if fwd.CircID != 0x80000002 {
		t.Fatalf("rewritten circID=%#x", fwd.CircID)
	}
	if !bytes.Equal(fwd.Payload, inner) {
		t.Fatal("peeled payload mismatch")
	}

	ret := make([]byte, 509)
	ret[0] = cell.RelayData
	ret[11] = 0xCD
	if err := ch.forwarder.forwardCellToClient(ext, &cell.Cell{
		CircID:  0x80000002,
		Command: cell.CmdRelay,
		Payload: ret,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := cell.DecodeCell(bytes.NewReader(clientConn.writeData))
	if err != nil {
		t.Fatal(err)
	}
	if got.CircID != 100 || got.Command != cell.CmdRelay {
		t.Fatalf("return cell circ=%d cmd=%d", got.CircID, got.Command)
	}
	plain := clientDecryptFromHop(t, km, got.Payload)
	if plain[11] != 0xCD {
		t.Fatalf("return payload byte=%#x", plain[11])
	}
}

func TestDestroyFromNextHopTearsDown(t *testing.T) {
	log := logger.NewDefault()
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	ch := NewCircuitHandler(keys, log)
	ch.mu.Lock()
	ch.circuits[100] = &ServerCircuit{CircuitID: 100, Created: time.Now(), LastActivity: time.Now()}
	ch.mu.Unlock()

	nextHop := newTestMockConn()
	clientConn := newTestMockConn()
	if err := ch.forwarder.RegisterExtendedCircuit(100, 0x80000003, "192.0.2.8:9001", nextHop); err != nil {
		t.Fatal(err)
	}
	ch.forwarder.extendedMu.Lock()
	ch.forwarder.extended[100].ClientConn = clientConn
	ch.forwarder.extendedMu.Unlock()

	ch.forwarder.DeliverFromNextHop("192.0.2.8:9001", &cell.Cell{
		CircID:  0x80000003,
		Command: cell.CmdDestroy,
		Payload: []byte{cell.DestroyReasonDestroyed},
	})

	if ch.forwarder.GetExtendedCircuitCount() != 0 {
		t.Fatalf("extended leftover=%d", ch.forwarder.GetExtendedCircuitCount())
	}
	if _, ok := ch.GetCircuit(100); ok {
		t.Fatal("inbound circuit should be closed")
	}
	got, err := cell.DecodeCell(bytes.NewReader(clientConn.writeData))
	if err != nil {
		t.Fatal(err)
	}
	if got.CircID != 100 || got.Command != cell.CmdDestroy {
		t.Fatalf("client cell circ=%d cmd=%d", got.CircID, got.Command)
	}
	if nextHop.closed {
		t.Fatal("pooled next-hop conn must stay open")
	}
}

func TestOutboundLinkHandshakeThenCreate2MSB(t *testing.T) {
	keys := generateTestRelayKeys(t)
	serverConn, clientConn := bufferedPipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})

	responder := NewLinkProtocolHandler(keys, nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := responder.HandleConnection(context.Background(), serverConn)
		errCh <- err
	}()

	cfg := connection.DefaultConfig("192.0.2.9:9001")
	cfg.ExpectedIdentity = append([]byte(nil), keys.Ed25519Public...)
	cfg.ExpectedFingerprint = fmt.Sprintf("%X", keys.RSANodeID())
	cfg.RequireCERTS = true
	or := connection.New(cfg, logger.NewDefault())
	or.AttachOpenConn(clientConn)

	ext := NewExtensionHandler(keys, NewCircuitHandler(keys, logger.NewDefault()), logger.NewDefault())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := ext.performLinkHandshake(ctx, or); err != nil {
		t.Fatalf("outbound handshake: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("responder handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("responder handshake timeout")
	}

	circID := newOutboundCircID()
	if circID&0x80000000 == 0 {
		t.Fatal("CREATE2 CircID missing MSB")
	}
	if err := ext.sendCreate2ToNextHop(or, circID, 0x0002, bytes.Repeat([]byte{0x11}, 84)); err != nil {
		t.Fatalf("CREATE2: %v", err)
	}
	got, err := cell.DecodeCellLink(serverConn, 4)
	if err != nil {
		t.Fatalf("read CREATE2: %v", err)
	}
	if got.Command != cell.CmdCreate2 {
		t.Fatalf("after handshake expected CREATE2, got %s（旧实现会先读到 CERTS）", got.Command)
	}
	if got.CircID != circID || got.CircID&0x80000000 == 0 {
		t.Fatalf("CREATE2 circID=%#x", got.CircID)
	}
}
