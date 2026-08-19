package connection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestTLSConfig_SessionTicketsDisabled 保证生产配置关闭会话恢复（gosec G123）。
func TestTLSConfig_SessionTicketsDisabled(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		cfg := createTorTLSConfig()
		if !cfg.SessionTicketsDisabled {
			t.Error("createTorTLSConfig SessionTicketsDisabled = false, want true")
		}
	})
	t.Run("pinning", func(t *testing.T) {
		cfg := createTorTLSConfigWithPinning(make([]byte, 32), "fp")
		if !cfg.SessionTicketsDisabled {
			t.Error("createTorTLSConfigWithPinning SessionTicketsDisabled = false, want true")
		}
	})
}

// TestTLSConfig_VerifyConnectionUsed 确认校验挂在恢复路径也会调用的钩子上。
func TestTLSConfig_VerifyConnectionUsed(t *testing.T) {
	cfgs := []*tls.Config{
		createTorTLSConfig(),
		createTorTLSConfigWithPinning(make([]byte, 32), "fp"),
	}
	for i, cfg := range cfgs {
		if cfg.VerifyConnection == nil {
			t.Errorf("cfg[%d] VerifyConnection = nil", i)
		}
		if cfg.VerifyPeerCertificate != nil {
			t.Errorf("cfg[%d] VerifyPeerCertificate 仍被设置，会话恢复会跳过它", i)
		}
	}
}

// TestVerifyConnection_DidResumeStillValidates 会话恢复时 crypto/tls 仍会调用
// VerifyConnection（DidResume=true）；过期证书必须被拒绝，有效证书必须通过。
func TestVerifyConnection_DidResumeStillValidates(t *testing.T) {
	valid, err := generateResumeLeaf()
	if err != nil {
		t.Fatalf("生成有效证书: %v", err)
	}
	if err := verifyTorRelayConnection(tls.ConnectionState{
		DidResume:        true,
		PeerCertificates: []*x509.Certificate{valid},
	}); err != nil {
		t.Fatalf("恢复会话的有效证书被拒绝: %v", err)
	}

	expired, err := generateResumeLeafAt(time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("生成过期证书: %v", err)
	}
	if err := verifyTorRelayConnection(tls.ConnectionState{
		DidResume:        true,
		PeerCertificates: []*x509.Certificate{expired},
	}); err == nil {
		t.Fatal("恢复会话的过期证书必须被拒绝，不能因 DidResume 跳过校验")
	}

	if err := verifyTorRelayConnection(tls.ConnectionState{DidResume: true}); err == nil {
		t.Fatal("恢复会话但没有对端证书必须被拒绝")
	}
}

// TestTLSConfig_SessionResumeStillVerifies 证明即使强制开启 tickets，
// VerifyConnection 在 DidResume=true 时仍会执行自定义校验。
func TestTLSConfig_SessionResumeStillVerifies(t *testing.T) {
	cert, err := generateResumeTestCert()
	if err != nil {
		t.Fatalf("生成测试证书: %v", err)
	}

	// 固定 TLS 1.2：票证在握手内发送，比 TLS 1.3 的握手后 ticket 更稳定。
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	defer ln.Close()

	go acceptTLS(t, ln)

	var verifyCalls atomic.Int32
	cache := &notifySessionCache{
		inner:  tls.NewLRUClientSessionCache(4),
		stored: make(chan struct{}, 4),
	}

	clientCfg := createTorTLSConfig()
	// 仅为验证恢复路径仍走校验：临时打开 tickets。生产配置保持关闭。
	clientCfg.SessionTicketsDisabled = false
	clientCfg.ClientSessionCache = cache
	clientCfg.MinVersion = tls.VersionTLS12
	clientCfg.MaxVersion = tls.VersionTLS12
	clientCfg.ServerName = "127.0.0.1"
	origVerify := clientCfg.VerifyConnection
	clientCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		verifyCalls.Add(1)
		if origVerify != nil {
			return origVerify(cs)
		}
		return nil
	}

	dial := func() *tls.Conn {
		t.Helper()
		conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
		if err != nil {
			t.Fatalf("TLS 拨号: %v", err)
		}
		return conn
	}

	c1 := dial()
	if c1.ConnectionState().DidResume {
		c1.Close()
		t.Fatal("第一次握手不应恢复会话")
	}
	if verifyCalls.Load() != 1 {
		c1.Close()
		t.Fatalf("第一次握手 VerifyConnection 调用次数 = %d, want 1", verifyCalls.Load())
	}
	drainSessionTickets(c1)
	waitSessionStored(t, cache)
	c1.Close()

	c2 := dial()
	defer c2.Close()
	if !c2.ConnectionState().DidResume {
		t.Fatal("第二次握手应恢复会话；否则无法证明恢复路径仍校验")
	}
	if verifyCalls.Load() != 2 {
		t.Fatalf("会话恢复后 VerifyConnection 调用次数 = %d, want 2（恢复不得跳过校验）", verifyCalls.Load())
	}
}

// TestTLSConfig_ProductionConfigDoesNotResume 生产配置关闭 tickets 后第二次连接不得恢复。
func TestTLSConfig_ProductionConfigDoesNotResume(t *testing.T) {
	cert, err := generateResumeTestCert()
	if err != nil {
		t.Fatalf("生成测试证书: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	defer ln.Close()
	go acceptTLS(t, ln)

	var verifyCalls atomic.Int32
	clientCfg := createTorTLSConfig()
	if !clientCfg.SessionTicketsDisabled {
		t.Fatal("生产配置必须 SessionTicketsDisabled=true")
	}
	clientCfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	clientCfg.ServerName = "127.0.0.1"
	origVerify := clientCfg.VerifyConnection
	clientCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		verifyCalls.Add(1)
		return origVerify(cs)
	}

	c1, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("第一次拨号: %v", err)
	}
	if _, err := c1.Write([]byte("ping")); err != nil {
		c1.Close()
		t.Fatalf("第一次写出: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	c1.Close()

	c2, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("第二次拨号: %v", err)
	}
	defer c2.Close()
	if c2.ConnectionState().DidResume {
		t.Error("生产配置禁用 session tickets 后不应恢复会话")
	}
	if verifyCalls.Load() != 2 {
		t.Fatalf("两次完整握手 VerifyConnection 调用次数 = %d, want 2", verifyCalls.Load())
	}
}

type notifySessionCache struct {
	inner  tls.ClientSessionCache
	stored chan struct{}
}

func (c *notifySessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	return c.inner.Get(sessionKey)
}

func (c *notifySessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.inner.Put(sessionKey, cs)
	if cs == nil {
		return
	}
	select {
	case c.stored <- struct{}{}:
	default:
	}
}

func waitSessionStored(t *testing.T, cache *notifySessionCache) {
	t.Helper()
	select {
	case <-cache.stored:
	case <-time.After(2 * time.Second):
		t.Fatal("等待会话票证超时")
	}
}

// drainSessionTickets 读出握手后的 NewSessionTicket，写入 ClientSessionCache。
func drainSessionTickets(conn *tls.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Read(make([]byte, 1))
	_ = conn.SetReadDeadline(time.Time{})
}

func acceptTLS(t *testing.T, ln net.Listener) {
	t.Helper()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}(conn)
	}
}

func generateResumeLeaf() (*x509.Certificate, error) {
	return generateResumeLeafAt(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func generateResumeLeafAt(notBefore, notAfter time.Time) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := resumeCertTemplate(notBefore, notAfter)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func generateResumeTestCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := resumeCertTemplate(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func resumeCertTemplate(notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-or"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
}
