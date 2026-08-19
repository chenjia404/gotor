package control

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestSignalNewnymAndShutdown(t *testing.T) {
	newnym := make(chan struct{}, 1)
	shutdown := make(chan struct{}, 1)
	log := logger.NewDefault()
	srv := NewServer("127.0.0.1:0", nil, log)
	srv.SetNewnymHandler(func() { newnym <- struct{}{} })
	srv.SetShutdownHandler(func() { shutdown <- struct{}{} })
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
	// skip greeting
	_, _ = r.ReadString('\n')
	mustControlCmd(t, w, r, "AUTHENTICATE\r\n", "250")
	mustControlCmd(t, w, r, "SIGNAL NEWNYM\r\n", "250")
	select {
	case <-newnym:
	case <-time.After(time.Second):
		t.Fatal("NEWNYM handler not called")
	}
	mustControlCmd(t, w, r, "SIGNAL CLEARDNSCACHE\r\n", "250")
	mustControlCmd(t, w, r, "SIGNAL SHUTDOWN\r\n", "250")
	select {
	case <-shutdown:
	case <-time.After(time.Second):
		t.Fatal("SHUTDOWN handler not called")
	}
	mustControlCmd(t, w, r, "SIGNAL BOGUS\r\n", "552")
}

func mustControlCmd(t *testing.T, w *bufio.Writer, r *bufio.Reader, cmd, wantPrefix string) {
	t.Helper()
	if _, err := w.WriteString(cmd); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("cmd %q -> %q want prefix %s", cmd, line, wantPrefix)
	}
}
