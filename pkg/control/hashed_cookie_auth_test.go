package control

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestAuthenticateHashedControlPassword(t *testing.T) {
	hashed, err := config.HashControlPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	mockClient := &mockClientGetter{socksPort: 9050, controlPort: 9051}
	log := logger.NewDefault()
	srv := NewServerWithAuth("127.0.0.1:0", mockClient, AuthOptions{
		HashedControlPassword: hashed,
	}, log)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	_, _ = r.ReadString('\n')
	_, _ = w.WriteString("AUTHENTICATE \"s3cret\"\r\n")
	_ = w.Flush()
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("want ok, got %s", line)
	}
}

func TestCookieAuthenticationWritesFile(t *testing.T) {
	dir := t.TempDir()
	cookie := filepath.Join(dir, "control_auth_cookie")
	mockClient := &mockClientGetter{socksPort: 9050, controlPort: 9051, dataDir: dir}
	log := logger.NewDefault()
	srv := NewServerWithAuth("127.0.0.1:0", mockClient, AuthOptions{
		CookieAuthentication: true,
		CookieAuthFile:       cookie,
	}, log)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	raw, err := os.ReadFile(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("cookie len %d", len(raw))
	}

	addr := srv.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	_, _ = r.ReadString('\n')

	_, _ = w.WriteString("AUTHENTICATE " + hex.EncodeToString(raw) + "\r\n")
	_ = w.Flush()
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("cookie auth: %s", line)
	}
}
