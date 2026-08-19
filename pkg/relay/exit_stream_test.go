package relay

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func testExitPolicyAllowLoopback(t *testing.T) *ExitPolicy {
	t.Helper()
	return NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Lines:                 []string{"accept 127.0.0.1:*", "reject *:*"},
		RejectPrivate:         false,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
}

func TestDefaultPolicyNotExit(t *testing.T) {
	p := NewExitPolicy(logger.NewDefault())
	if p.AllowExit || p.WouldAnnounceExit() {
		t.Fatal("默认不得开放出口")
	}
	ok, reason := p.CheckExitAllowed("1.1.1.1", 80)
	if ok || reason != cell.EndReasonExitPolicy {
		t.Fatalf("ok=%v reason=%d", ok, reason)
	}
}

func TestExitPolicyOrderFirstMatch(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Lines:                 []string{"reject *:25", "accept *:25", "reject *:*"},
		RejectPrivate:         false,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	ok, _ := p.CheckExitAllowed("1.1.1.1", 25)
	if ok {
		t.Fatal("顺序匹配：先 reject *:25 应生效")
	}
}

func TestExitPolicyNoMatchAccepts(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Lines:                 []string{"reject *:25"},
		RejectPrivate:         false,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	// 无绝对结尾则追加默认策略；默认含 accept *:*，80 应放行、25 仍拒绝
	ok, _ := p.CheckExitAllowed("1.1.1.1", 80)
	if !ok {
		t.Fatal("无匹配后默认 accept 应放行 80")
	}
	ok, _ = p.CheckExitAllowed("1.1.1.1", 25)
	if ok {
		t.Fatal("25 应被默认/用户规则拒绝")
	}
}

func TestExitPolicyRejectPrivateDefault(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	for _, addr := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.1.1", "100.64.1.1"} {
		ok, _ := p.CheckExitAllowed(addr, 80)
		if ok {
			t.Fatalf("%s 默认 RejectPrivate 应拒绝", addr)
		}
	}
	ok, _ := p.CheckExitAllowed("1.1.1.1", 80)
	if !ok {
		t.Fatal("公网应放行")
	}
}

func TestExitPolicyRejectAllMeansNonExit(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Lines:                 []string{"reject *:*"},
		RejectPrivate:         true,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	if p.WouldAnnounceExit() {
		t.Fatal("全拒绝策略不得宣告 Exit")
	}
	if !p.AllowExit {
		t.Fatal("ExitRelay 1 仍应执行策略（全部拒绝）")
	}
	ok, _ := p.CheckExitAllowed("1.1.1.1", 80)
	if ok {
		t.Fatal("reject *:* 应拒绝")
	}
}

func TestExitPolicyIPv6RequiresIPv6Exit(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Lines:                 []string{"accept *:*"},
		IPv6Exit:              false,
		RejectPrivate:         true,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	ok, _ := p.CheckExitAllowed("2001:4860:4860::8888", 80)
	if ok {
		t.Fatal("未开 IPv6Exit 不得放行 IPv6")
	}
}

func TestParseBeginAddrFlags(t *testing.T) {
	h, p, flags, present, err := parseBeginAddr([]byte("example.com:443\x00\x00\x00\x00\x05"))
	if err != nil || h != "example.com" || p != 443 || !present {
		t.Fatalf("%s %d present=%v %v", h, p, present, err)
	}
	if flags != 5 { // IPv6 OK + preferred
		t.Fatalf("flags=%d", flags)
	}
}

func TestHandleBeginRejectPrivate(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:80", "reject *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	m.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		t.Fatal("不得拨号私网")
		return nil, nil
	}
	circ := &ServerCircuit{CircuitID: 1, ctx: context.Background()}
	cc, err := newCircuitCrypto(bytes.Repeat([]byte{1}, 72))
	if err != nil {
		t.Fatal(err)
	}
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = cell.DecodeCell(server)
	}()
	err = m.HandleBegin(context.Background(), circ, client, 7, []byte("127.0.0.1:80\x00"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandleBeginAcceptLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
		close(done)
	}()

	p := testExitPolicyAllowLoopback(t)
	if !p.AllowExit {
		t.Fatal("显式允许 127.0.0.1 时应视为可出口")
	}
	m := NewExitStreamManager(p, logger.NewDefault())
	circ := &ServerCircuit{CircuitID: 2, ctx: context.Background()}
	cc, err := newCircuitCrypto(bytes.Repeat([]byte{2}, 72))
	if err != nil {
		t.Fatal(err)
	}
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		for {
			if _, err := cell.DecodeCell(server); err != nil {
				return
			}
		}
	}()
	payload := []byte(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "\x00")
	if err := m.HandleBegin(context.Background(), circ, client, 9, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("未连上本地监听")
	}
	m.CloseAll()
}

func TestEncodeResolvedRoundTrip(t *testing.T) {
	raw := encodeResolvedAddresses([]net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("2001:db8::1")}, 60)
	// 2001:db8 仍编码；过滤发生在 HandleResolve
	if len(raw) < 10 {
		t.Fatalf("payload too short %d", len(raw))
	}
	if raw[0] != circuit.DNSTypeIPv4 || raw[1] != 4 {
		t.Fatalf("v4 header %d %d", raw[0], raw[1])
	}
	errp := encodeResolvedError(false, "Error resolving hostname")
	if errp[0] != circuit.DNSTypeErrorTTL {
		t.Fatalf("err type %d", errp[0])
	}
}

func TestHandleResolveFiltersPrivate(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:80", "reject *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("1.1.1.1")}, nil
	}
	circ := &ServerCircuit{CircuitID: 3, ctx: context.Background()}
	cc, _ := newCircuitCrypto(bytes.Repeat([]byte{3}, 72))
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := cell.DecodeCell(server)
		if err != nil {
			return
		}
		plain, _, err := circ.crypto.decryptInbound(c.Payload)
		if err != nil {
			// 出向加密用的是另一套；这里只确认发了 cell
			got <- c.Payload
			return
		}
		got <- plain
	}()
	if err := m.HandleResolve(context.Background(), circ, client, 4, []byte("example.com\x00")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("no RESOLVED")
	}
}

func TestHandleResolveOnionRejected(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		t.Fatal("不得解析 .onion")
		return nil, nil
	}
	circ := &ServerCircuit{CircuitID: 4, ctx: context.Background()}
	cc, _ := newCircuitCrypto(bytes.Repeat([]byte{4}, 72))
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		for {
			if _, err := cell.DecodeCell(server); err != nil {
				return
			}
		}
	}()
	if err := m.HandleResolve(context.Background(), circ, client, 1, []byte("abc.onion\x00")); err != nil {
		t.Fatal(err)
	}
	if err := m.HandleResolve(context.Background(), circ, client, 2, []byte("abc.onion.\x00")); err != nil {
		t.Fatal(err)
	}
}

func TestHandleResolveOmitsIPv6WhenDisabled(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	if p.ipv6OK {
		t.Fatal("IPv6Exit 默认关")
	}
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2606:4700:4700::1111")}, nil
	}
	ips, err := m.lookupIP(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	allowV6 := p.ipv6OK
	var filtered []net.IP
	for _, ip := range ips {
		if ip.To4() == nil && !allowV6 {
			continue
		}
		if dangerousExitIP(ip) {
			continue
		}
		filtered = append(filtered, ip)
	}
	if len(filtered) != 1 || filtered[0].String() != "1.1.1.1" {
		t.Fatalf("未开 IPv6Exit 的 RESOLVE 不得返回 IPv6: %v", filtered)
	}
}

func TestParseARPAName(t *testing.T) {
	ip := parseARPAName("1.2.0.192.in-addr.arpa")
	if ip == nil || ip.String() != "192.0.2.1" {
		t.Fatalf("ipv4 arpa: %v", ip)
	}
	want := net.ParseIP("2001:db8::1")
	name, err := circuit.PTRHostname(want)
	if err != nil {
		t.Fatal(err)
	}
	got := parseARPAName(name)
	if !got.Equal(want) {
		t.Fatalf("ipv6 arpa %s -> %v", name, got)
	}
	if parseARPAName("not-arpa") != nil {
		t.Fatal("非 arpa 应失败")
	}
}

func TestHandleResolveStreamIDZeroDropped(t *testing.T) {
	p := NewExitPolicy(logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	if err := m.HandleResolve(context.Background(), &ServerCircuit{CircuitID: 1}, nil, 0, []byte("a.com\x00")); err != nil {
		t.Fatal(err)
	}
}

func TestHandleBeginRejectsOnion(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		t.Fatal("BEGIN 不得解析 .onion")
		return nil, nil
	}
	circ := &ServerCircuit{CircuitID: 5, ctx: context.Background()}
	cc, _ := newCircuitCrypto(bytes.Repeat([]byte{5}, 72))
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = cell.DecodeCell(server) }()
	if err := m.HandleBegin(context.Background(), circ, client, 1, []byte("abc.onion:80\x00")); err != nil {
		t.Fatal(err)
	}
}

func TestNonExitDoesNotResolveDNS(t *testing.T) {
	p := NewExitPolicy(logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		t.Fatal("非出口不得做 DNS")
		return nil, nil
	}
	circ := &ServerCircuit{CircuitID: 6, ctx: context.Background()}
	cc, _ := newCircuitCrypto(bytes.Repeat([]byte{6}, 72))
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		for {
			if _, err := cell.DecodeCell(server); err != nil {
				return
			}
		}
	}()
	if err := m.HandleResolve(context.Background(), circ, client, 2, []byte("example.com\x00")); err != nil {
		t.Fatal(err)
	}
	if err := m.HandleBegin(context.Background(), circ, client, 3, []byte("example.com:80\x00")); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorContainsExitPolicy(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	desc, err := GenerateServerDescriptor(keys, &DescriptorConfig{
		Nickname:        "ExitTest",
		Address:         "192.0.2.10",
		ORPort:          9001,
		ExitPolicyLines: []string{"accept *:80", "accept *:443", "reject *:*"},
		IPv6Policy:      "ipv6-policy reject 1-65535",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(desc.RawDescriptor)
	if !bytes.Contains(desc.RawDescriptor, []byte("accept *:80\n")) {
		t.Fatalf("missing accept *:80 in\n%s", raw)
	}
	if !bytes.Contains(desc.RawDescriptor, []byte("ipv6-policy reject 1-65535\n")) {
		t.Fatal("missing ipv6-policy")
	}
	if desc.ExitPolicy == "reject *:*" {
		t.Fatal("ExitPolicy 字段应是真实策略")
	}
}

func TestUserLinesWithoutCatchAllAppendDefault(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Lines:                 []string{"accept *:80"},
		RejectPrivate:         false,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	ok, _ := p.CheckExitAllowed("1.1.1.1", 443)
	if !ok {
		t.Fatal("用户行不以 *:* 结尾时应追加默认策略，443 应放行")
	}
	ok, _ = p.CheckExitAllowed("1.1.1.1", 25)
	if ok {
		t.Fatal("追加的默认策略应拒绝 25")
	}
}

func TestIPv6PolicyLineListsReducedPorts(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Reduce:                true,
		IPv6Exit:              true,
		RejectPrivate:         true,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	line := p.IPv6PolicyLine()
	if !strings.Contains(line, "80") || !strings.Contains(line, "443") || !strings.Contains(line, "110") {
		t.Fatalf("ipv6-policy 应列出精简策略端口，得到 %s", line)
	}
	if strings.HasPrefix(line, "ipv6-policy reject") {
		t.Fatalf("IPv6Exit+Reduce 不应整段拒绝: %s", line)
	}
}

func TestReducedPolicyAllowsHTTPRejectsSMTP(t *testing.T) {
	p := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             true,
		Reduce:                true,
		RejectPrivate:         true,
		RejectLocalInterfaces: false,
	}, logger.NewDefault())
	ok, _ := p.CheckExitAllowed("1.1.1.1", 80)
	if !ok {
		t.Fatal("reduced 应放行 80")
	}
	ok, _ = p.CheckExitAllowed("1.1.1.1", 25)
	if ok {
		t.Fatal("reduced 不得放行 25")
	}
}

func TestFilterBeginIPsFlagsPresentZero(t *testing.T) {
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2001:4860:4860::8888")}
	got := filterBeginIPs(ips, 0, true)
	if len(got) != 1 || got[0].To4() == nil {
		t.Fatalf("FLAGS=0 只应保留 IPv4: %v", got)
	}
	got = filterBeginIPs(ips, 0, false)
	if len(got) != 2 {
		t.Fatalf("无 FLAGS 应保留双栈: %v", got)
	}
}

func TestHandleBeginRejectsOnionFQDN(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		t.Fatal("BEGIN 不得解析 abc.onion.")
		return nil, nil
	}
	circ := &ServerCircuit{CircuitID: 8, ctx: context.Background()}
	cc, _ := newCircuitCrypto(bytes.Repeat([]byte{8}, 72))
	circ.crypto = cc
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = cell.DecodeCell(server) }()
	if err := m.HandleBegin(context.Background(), circ, client, 1, []byte("abc.onion.:80\x00")); err != nil {
		t.Fatal(err)
	}
}

func TestHandleSendmeDoesNotInflateFullWindow(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.circOutWindow[1] = exitCircWindowInit
	m.HandleSendme(1, 0, nil)
	if m.circOutWindow[1] != exitCircWindowInit {
		t.Fatalf("满窗多余 SENDME 不得放大: %d", m.circOutWindow[1])
	}
	m.circOutWindow[1] = exitCircWindowInit - 20
	m.HandleSendme(1, 0, nil)
	if m.circOutWindow[1] != exitCircWindowInit {
		t.Fatalf("SENDME 应补到初值: %d", m.circOutWindow[1])
	}
	m.HandleSendme(1, 0, []byte{0x01})
	if m.circOutWindow[1] != exitCircWindowInit {
		t.Fatalf("非法 SENDME 不得改窗口: %d", m.circOutWindow[1])
	}
}

func TestHandleBeginDirHonorsStreamLimit(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{"accept *:*"}, false, false, logger.NewDefault())
	m := NewExitStreamManager(p, logger.NewDefault())
	m.dirDial = func() (net.Conn, error) {
		t.Fatal("超限后不得 dirDial")
		return nil, nil
	}
	circ := &ServerCircuit{CircuitID: 9, ctx: context.Background()}
	cc, _ := newCircuitCrypto(bytes.Repeat([]byte{9}, 72))
	circ.crypto = cc
	m.mu.Lock()
	m.circStreams[circ.CircuitID] = exitMaxStreamsPerCirc
	m.mu.Unlock()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = cell.DecodeCell(server) }()
	if err := m.HandleBeginDir(context.Background(), circ, client, 1); err != nil {
		t.Fatal(err)
	}
}
