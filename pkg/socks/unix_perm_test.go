package socks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestUnixSocksSocketMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket 权限模型与 POSIX 不同")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "socks.sock")
	cfg := DefaultConfig()
	cfg.Network = "unix"
	s := NewServerWithConfig(path, circuit.NewManager(), logger.NewDefault(), cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("unix socket: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("unix SOCKS 权限 %o，期望 0600", st.Mode().Perm())
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
}
