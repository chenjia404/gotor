package control

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestSafeCookieAuthChallengeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cookiePath := filepath.Join(dir, "control_auth_cookie")
	cookie := make([]byte, 32)
	if _, err := rand.Read(cookie); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cookiePath, cookie, 0o600); err != nil {
		t.Fatal(err)
	}

	srv := NewServerWithAuth("127.0.0.1:0", nil, AuthOptions{
		CookieAuthentication: true,
		CookieAuthFile:       cookiePath,
	}, logger.NewDefault())
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cookie, err := os.ReadFile(cookiePath)
	if err != nil || len(cookie) != 32 {
		t.Fatalf("cookie after start: %v len=%d", err, len(cookie))
	}

	addr := srv.listener.Addr().String()
	var conn net.Conn
	for i := 0; i < 20; i++ {
		conn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	_, _ = r.ReadString('\n') // greeting

	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("AUTHCHALLENGE SAFECOOKIE " + hex.EncodeToString(clientNonce) + "\r\n")
	_ = w.Flush()

	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "250 AUTHCHALLENGE") {
		t.Fatalf("unexpected: %q", line)
	}
	fields := strings.Fields(line)
	var serverHashHex, serverNonceHex string
	for _, f := range fields {
		if strings.HasPrefix(f, "SERVERHASH=") {
			serverHashHex = strings.TrimPrefix(f, "SERVERHASH=")
		}
		if strings.HasPrefix(f, "SERVERNONCE=") {
			serverNonceHex = strings.TrimPrefix(f, "SERVERNONCE=")
		}
	}
	serverNonce, err := hex.DecodeString(serverNonceHex)
	if err != nil || len(serverNonce) != 32 {
		t.Fatalf("bad server nonce %q", serverNonceHex)
	}
	msg := append(append(append([]byte{}, cookie...), clientNonce...), serverNonce...)
	wantServer := hmac.New(sha256.New, []byte(safeCookieServerToController))
	wantServer.Write(msg)
	gotServer, _ := hex.DecodeString(serverHashHex)
	if !hmac.Equal(wantServer.Sum(nil), gotServer) {
		t.Fatal("SERVERHASH mismatch")
	}
	clientMAC := hmac.New(sha256.New, []byte(safeCookieControllerToServer))
	clientMAC.Write(msg)
	clientHash := clientMAC.Sum(nil)

	_, _ = w.WriteString("AUTHENTICATE " + hex.EncodeToString(clientHash) + "\r\n")
	_ = w.Flush()
	authLine, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(authLine, "250") {
		t.Fatalf("auth failed: %q", authLine)
	}

	// PROTOCOLINFO 应宣告 SAFECOOKIE
	_, _ = w.WriteString("PROTOCOLINFO 1\r\n")
	_ = w.Flush()
	var methodsLine string
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(l, "METHODS=") {
			methodsLine = l
		}
		if strings.HasPrefix(l, "250 ") {
			break
		}
	}
	if !strings.Contains(methodsLine, "SAFECOOKIE") {
		t.Fatalf("PROTOCOLINFO missing SAFECOOKIE: %q", methodsLine)
	}
}
