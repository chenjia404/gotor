package onion

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

type MockCircuit struct {
	id        uint32
	sentCells []*cell.RelayCell
	sendError error
}

func (m *MockCircuit) SendRelayCell(c *cell.RelayCell) error {
	if m.sendError != nil {
		return m.sendError
	}
	m.sentCells = append(m.sentCells, c)
	return nil
}

func (m *MockCircuit) ReceiveRelayCell(ctx context.Context) (*cell.RelayCell, error) {
	return nil, context.Canceled
}

func (m *MockCircuit) GetID() uint32 {
	return m.id
}

func TestBuildRendezvous1CellHsNtor(t *testing.T) {
	bPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	X, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	B, err := curve25519.X25519(bPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	authKey := make([]byte, 32)
	if _, err := rand.Read(authKey); err != nil {
		t.Fatal(err)
	}
	cookie := make([]byte, 20)
	if _, err := rand.Read(cookie); err != nil {
		t.Fatal(err)
	}
	yPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	rc, seed, err := BuildRendezvous1Cell(cookie, X, bPriv, authKey, yPriv, 1, 0)
	if err != nil {
		t.Fatalf("BuildRendezvous1Cell: %v", err)
	}
	if rc.Command != cell.RelayRendezvous1 {
		t.Fatalf("cmd=%d", rc.Command)
	}
	if len(rc.Data) != 84 {
		t.Fatalf("payload len=%d", len(rc.Data))
	}
	if !bytes.Equal(rc.Data[:20], cookie) {
		t.Fatal("cookie mismatch")
	}
	if len(seed) != crypto.HsNtorKeySeedLen {
		t.Fatalf("seed len=%d", len(seed))
	}

	clientSeed, err := crypto.HsNtorClientRend(xPriv, B, authKey, rc.Data[20:84])
	if err != nil {
		t.Fatalf("client rend: %v", err)
	}
	if !bytes.Equal(clientSeed, seed) {
		t.Fatal("client/server NTOR_KEY_SEED mismatch")
	}
}

func TestBuildRendezvous1CellRejectsBadLengths(t *testing.T) {
	_, _, err := BuildRendezvous1Cell(make([]byte, 19), make([]byte, 32), make([]byte, 32), make([]byte, 32), nil, 1, 0)
	if err == nil {
		t.Fatal("short cookie must fail")
	}
	_, _, err = BuildRendezvous1Cell(make([]byte, 20), make([]byte, 32), make([]byte, 32), make([]byte, 20), nil, 1, 0)
	if err == nil {
		t.Fatal("short auth key must fail")
	}
}

func TestSendRendezvous1(t *testing.T) {
	bPriv, _ := crypto.GenerateCurve25519PrivateKey()
	xPriv, _ := crypto.GenerateCurve25519PrivateKey()
	X, _ := curve25519.X25519(xPriv, curve25519.Basepoint)
	authKey := make([]byte, 32)
	_, _ = rand.Read(authKey)
	cookie := make([]byte, 20)
	_, _ = rand.Read(cookie)
	mock := &MockCircuit{id: 7}
	seed, err := SendRendezvous1(mock, 7, cookie, X, bPriv, authKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.sentCells) != 1 {
		t.Fatalf("sent=%d", len(mock.sentCells))
	}
	if len(seed) != 32 {
		t.Fatalf("seed=%d", len(seed))
	}
}
