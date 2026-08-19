package onion

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/logger"
	"golang.org/x/crypto/curve25519"
)

type mockHSCellSender struct {
	rendezvous2 []byte
}

func (m *mockHSCellSender) SendRelayCell(ctx context.Context, circuitID uint32, command uint8, data []byte) error {
	return nil
}

func (m *mockHSCellSender) ReceiveRelayCell(ctx context.Context, circuitID uint32, timeout time.Duration) ([]byte, error) {
	return append([]byte(nil), m.rendezvous2...), nil
}

func TestCompleteRendezvousHsNtor(t *testing.T) {
	authKey := make([]byte, 32)
	authKey[0] = 0xAA
	bPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	B, err := curve25519.X25519(bPriv, curve25519.Basepoint)
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
	yPriv, err := crypto.GenerateCurve25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	resp, seed, err := crypto.HsNtorServiceRend(yPriv, bPriv, X, authKey)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(logger.NewDefault())
	circID := uint32(42)
	st := &RendezvousState{CircuitID: circID}
	copy(st.EphemeralPrivate[:], xPriv)
	copy(st.EphemeralPublic[:], X)
	copy(st.IntroEncKeyB[:], B)
	copy(st.IntroAuthKey[:], authKey)
	client.StoreRendezvousState(circID, st)
	client.SetCellSender(&mockHSCellSender{rendezvous2: resp})

	if err := client.CompleteRendezvous(context.Background(), circID); err != nil {
		t.Fatalf("CompleteRendezvous: %v", err)
	}
	if _, ok := client.GetRendezvousState(circID); ok {
		t.Fatal("state should be removed after success")
	}

	// 校验 seed 可再展开（服务端侧对照）
	keys, err := crypto.HsNtorExpandCircuitKeys(seed)
	if err != nil || len(keys) != crypto.HsNtorCircuitKeyLen {
		t.Fatalf("expand: %v len=%d", err, len(keys))
	}
	_ = bytes.Equal
}
