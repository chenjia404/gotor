package relay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
	"golang.org/x/crypto/curve25519"
)

func TestDefaultDirectoryAuthorities(t *testing.T) {
	auths := DefaultDirectoryAuthorities()
	if len(auths) < 9 {
		t.Fatalf("directory authorities %d, want >= 9", len(auths))
	}
	for _, a := range auths {
		if a.Address == "" || !strings.Contains(a.URL, "/tor/post/upload") {
			t.Fatalf("bad authority %+v", a)
		}
	}
}

func TestAuthorityUploadURLs(t *testing.T) {
	urls := authorityUploadURLs(BridgeAuthority{Address: "192.0.2.1:80", URL: "http://192.0.2.1/tor/post/upload"})
	if len(urls) < 2 || !strings.Contains(urls[1], "/tor/") {
		t.Fatalf("urls %v", urls)
	}
	plain := authorityUploadURLs(BridgeAuthority{Address: "192.0.2.1:80"})
	if len(plain) != 2 {
		t.Fatalf("plain urls %v", plain)
	}
}

func TestNewDescriptorPublisher(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	tests := []struct {
		name   string
		config PublisherConfig
	}{
		{
			name:   "default config",
			config: DefaultPublisherConfig(),
		},
		{
			name: "custom authorities",
			config: PublisherConfig{
				Authorities: []BridgeAuthority{
					{Address: "192.0.2.1:80", URL: "http://192.0.2.1/tor/"},
				},
			},
		},
		{
			name:   "empty config uses defaults",
			config: PublisherConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := NewDescriptorPublisher(tt.config, log)
			if pub == nil {
				t.Fatal("NewDescriptorPublisher returned nil")
			}
			if pub.httpClient == nil {
				t.Error("httpClient not initialized")
			}
			if len(pub.authorities) == 0 {
				t.Error("authorities list is empty")
			}
		})
	}
}

func TestPublishDescriptor_Success(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	// Create mock HTTP server
	var receivedData []byte
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/octet-stream" {
			t.Errorf("expected Content-Type application/octet-stream, got %s", contentType)
		}

		body, _ := io.ReadAll(r.Body)
		receivedData = body

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{Address: "test", URL: server.URL + "/tor/"},
		},
		HTTPTimeout: 5 * time.Second,
	}

	pub := NewDescriptorPublisher(config, log)

	// Create test descriptor
	descriptor := createTestDescriptor(t)

	ctx := context.Background()
	count, err := pub.PublishDescriptor(ctx, descriptor)
	if err != nil {
		t.Fatalf("PublishDescriptor failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 successful publish, got %d", count)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 HTTP request, got %d", requestCount)
	}

	if !strings.Contains(string(receivedData), "router TestRelay") {
		t.Error("received data does not contain expected descriptor content")
	}

	// Check stats
	lastPublish, pubCount := pub.GetStats()
	if lastPublish.IsZero() {
		t.Error("lastPublish should not be zero")
	}
	if pubCount != 1 {
		t.Errorf("publish count = %d, want 1", pubCount)
	}
}

func TestPublishDescriptor_MultipleAuthorities(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	var requestCount int32

	// Create 3 mock servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusAccepted) // 202 also accepted
	}))
	defer server2.Close()

	server3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server3.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server1.URL + "/tor/"},
			{URL: server2.URL + "/tor/"},
			{URL: server3.URL + "/tor/"},
		},
		HTTPTimeout: 5 * time.Second,
	}

	pub := NewDescriptorPublisher(config, log)
	descriptor := createTestDescriptor(t)

	ctx := context.Background()
	count, err := pub.PublishDescriptor(ctx, descriptor)
	if err != nil {
		t.Fatalf("PublishDescriptor failed: %v", err)
	}

	if count != 3 {
		t.Errorf("expected 3 successful publishes, got %d", count)
	}

	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("expected 3 HTTP requests, got %d", requestCount)
	}
}

func TestPublishDescriptor_PartialFailure(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	// Server 1: success
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	// Server 2: failure
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server2.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server1.URL + "/tor/"},
			{URL: server2.URL + "/tor/"},
		},
		HTTPTimeout:   5 * time.Second,
		RetryAttempts: 1, // Reduce retries for faster test
	}

	pub := NewDescriptorPublisher(config, log)
	descriptor := createTestDescriptor(t)

	ctx := context.Background()
	count, err := pub.PublishDescriptor(ctx, descriptor)
	// Should succeed partially (1 out of 2)
	if err != nil {
		t.Errorf("unexpected error with partial success: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 successful publish, got %d", count)
	}
}

func TestPublishDescriptor_AllFail(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Server error"))
	}))
	defer server.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server.URL + "/tor/"},
		},
		HTTPTimeout:   5 * time.Second,
		RetryAttempts: 1, // Reduce retries for faster test
	}

	pub := NewDescriptorPublisher(config, log)
	descriptor := createTestDescriptor(t)

	ctx := context.Background()
	count, err := pub.PublishDescriptor(ctx, descriptor)

	if err == nil {
		t.Error("expected error when all authorities fail")
	}

	if count != 0 {
		t.Errorf("expected 0 successful publishes, got %d", count)
	}
}

func TestPublishDescriptor_InvalidInput(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)
	pub := NewDescriptorPublisher(DefaultPublisherConfig(), log)
	ctx := context.Background()

	tests := []struct {
		name       string
		descriptor *ServerDescriptor
		wantErr    bool
	}{
		{
			name:       "nil descriptor",
			descriptor: nil,
			wantErr:    true,
		},
		{
			name:       "empty RawDescriptor",
			descriptor: &ServerDescriptor{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pub.PublishDescriptor(ctx, tt.descriptor)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublishDescriptor() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublishDescriptor_ContextCancellation(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	// Slow server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server.URL + "/tor/"},
		},
		HTTPTimeout: 5 * time.Second,
	}

	pub := NewDescriptorPublisher(config, log)
	descriptor := createTestDescriptor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := pub.PublishDescriptor(ctx, descriptor)
	if err == nil {
		t.Error("expected error due to context cancellation")
	}
}

func TestPublishDescriptorPairConcatenated(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pub := NewDescriptorPublisher(PublisherConfig{
		Authorities: []BridgeAuthority{{URL: server.URL + "/tor/"}},
	}, log)
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	desc, extra, err := GenerateDescriptorPair(keys, &DescriptorConfig{
		Nickname: "PairPub",
		Address:  "192.0.2.30",
		ORPort:   9001,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := pub.PublishDescriptorPair(context.Background(), desc, extra)
	if err != nil || n != 1 {
		t.Fatalf("pair publish %d %v", n, err)
	}
	body := string(received)
	if !strings.Contains(body, "router PairPub") {
		t.Fatal("POST 应含 server descriptor")
	}
	if !strings.Contains(body, "extra-info PairPub") {
		t.Fatal("POST 应含 extra-info")
	}
	if !strings.Contains(body, "extra-info-digest ") {
		t.Fatal("描述符应含 extra-info-digest")
	}
	if strings.Index(body, "router PairPub") > strings.Index(body, "extra-info PairPub") {
		t.Fatal("C Tor 顺序：先 router 再 extra-info")
	}
}

func TestPublishExtraInfo(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	var receivedData []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedData = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server.URL + "/tor/"},
		},
	}

	pub := NewDescriptorPublisher(config, log)

	extraInfo := &ExtraInfoDescriptor{
		Nickname:    "TestRelay",
		Fingerprint: "AAAA1234567890ABCDEF1234567890ABCDEF12",
		Statistics: map[string]string{
			"test-stat": "value",
		},
		RawDescriptor: []byte("extra-info TestRelay AAAA1234567890ABCDEF1234567890ABCDEF12\ntest-stat value\n"),
	}

	ctx := context.Background()
	count, err := pub.PublishExtraInfo(ctx, extraInfo)
	if err != nil {
		t.Fatalf("PublishExtraInfo failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 successful publish, got %d", count)
	}

	if !strings.Contains(string(receivedData), "extra-info TestRelay") {
		t.Error("received data does not contain expected extra-info content")
	}
}

func TestPublishExtraInfo_InvalidInput(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)
	pub := NewDescriptorPublisher(DefaultPublisherConfig(), log)
	ctx := context.Background()

	tests := []struct {
		name      string
		extraInfo *ExtraInfoDescriptor
		wantErr   bool
	}{
		{
			name:      "nil extra-info",
			extraInfo: nil,
			wantErr:   true,
		},
		{
			name:      "empty RawDescriptor",
			extraInfo: &ExtraInfoDescriptor{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pub.PublishExtraInfo(ctx, tt.extraInfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublishExtraInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScheduledPublisher(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	var publishCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&publishCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server.URL + "/tor/"},
		},
	}

	pub := NewDescriptorPublisher(config, log)

	var generateCallCount int32
	generateFunc := func() (*ServerDescriptor, *ExtraInfoDescriptor, error) {
		atomic.AddInt32(&generateCallCount, 1)
		return createTestDescriptor(t), nil, nil
	}

	scheduler := NewScheduledPublisher(pub, 50*time.Millisecond, generateFunc, log)

	ctx := context.Background()
	err := scheduler.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for at least 2 publish cycles
	time.Sleep(150 * time.Millisecond)

	scheduler.Stop()

	// Should have at least 2 publishes (initial + 1 scheduled)
	if atomic.LoadInt32(&publishCount) < 2 {
		t.Errorf("expected at least 2 publishes, got %d", publishCount)
	}

	if atomic.LoadInt32(&generateCallCount) < 2 {
		t.Errorf("expected at least 2 generate calls, got %d", generateCallCount)
	}
}

func TestScheduledPublisher_GateBlocksUntilAllowed(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)
	var publishCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&publishCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pub := NewDescriptorPublisher(PublisherConfig{
		Authorities: []BridgeAuthority{{URL: server.URL + "/tor/"}},
	}, log)
	allow := atomic.Bool{}
	sched := NewScheduledPublisher(pub, time.Hour, func() (*ServerDescriptor, *ExtraInfoDescriptor, error) {
		return createTestDescriptor(t), nil, nil
	}, log)
	sched.SetPublishGate(func() bool { return allow.Load() })

	ctx := context.Background()
	if err := sched.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sched.Stop()
	time.Sleep(40 * time.Millisecond)
	if atomic.LoadInt32(&publishCount) != 0 {
		t.Fatalf("门闩关闭时仍发布了 %d 次", publishCount)
	}

	allow.Store(true)
	sched.TriggerNow(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&publishCount) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&publishCount) == 0 {
		t.Fatal("门闩打开后 TriggerNow 未发布")
	}
}

func TestScheduledPublisher_StopIdempotent(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)
	pub := NewDescriptorPublisher(DefaultPublisherConfig(), log)

	generateFunc := func() (*ServerDescriptor, *ExtraInfoDescriptor, error) {
		return createTestDescriptor(t), nil, nil
	}

	scheduler := NewScheduledPublisher(pub, time.Hour, generateFunc, log)

	// Stop without starting should not panic
	scheduler.Stop()
	scheduler.Stop() // Second stop should be idempotent
}

func TestScheduledPublisher_DoubleStart(t *testing.T) {
	log := logger.New(slog.LevelInfo, io.Discard)

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := PublisherConfig{
		Authorities: []BridgeAuthority{
			{URL: server.URL + "/tor/"},
		},
		HTTPTimeout: 2 * time.Second,
	}

	pub := NewDescriptorPublisher(config, log)

	generateFunc := func() (*ServerDescriptor, *ExtraInfoDescriptor, error) {
		return createTestDescriptor(t), nil, nil
	}

	scheduler := NewScheduledPublisher(pub, time.Hour, generateFunc, log)

	ctx := context.Background()
	err := scheduler.Start(ctx)
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}

	// Give it a moment to start the initial publish
	time.Sleep(50 * time.Millisecond)
	defer scheduler.Stop()

	err = scheduler.Start(ctx)
	if err == nil {
		t.Error("expected error when starting already running scheduler")
	}
}

// Helper function to create a test descriptor
func createTestDescriptor(t *testing.T) *ServerDescriptor {
	t.Helper()

	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Generate ntor key
	ntorPrivate := make([]byte, 32)
	if _, err := rand.Read(ntorPrivate); err != nil {
		t.Fatalf("failed to generate ntor key: %v", err)
	}
	ntorPublic, _ := curve25519.X25519(ntorPrivate, curve25519.Basepoint)

	descriptor := &ServerDescriptor{
		Nickname:       "TestRelay",
		Address:        "192.0.2.1",
		ORPort:         9001,
		DirPort:        0,
		Platform:       "go-tor 0.1.0",
		PublishedTime:  time.Now().UTC(),
		BandwidthAvg:   1000000,
		BandwidthBurst: 2000000,
		BandwidthObs:   1500000,
		ExitPolicy:     "reject *:*",
		RSAIdentity:    &rsaKey.PublicKey,
		NtorOnionKey:   ntorPublic,
		rsaPrivate:     rsaKey,
		RawDescriptor:  []byte("router TestRelay 192.0.2.1 9001 0 0\n"),
	}

	return descriptor
}
