package onion

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

func TestBuildBlindedKeyParamIncludesNUL(t *testing.T) {
	pk := make([]byte, 32)
	pk[0] = 1
	p1, err := BuildBlindedKeyParam(pk, nil, 1, 1440)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 32 {
		t.Fatal(len(p1))
	}
	p2, _ := BuildBlindedKeyParam(pk, nil, 2, 1440)
	if bytes.Equal(p1, p2) {
		t.Fatal("period must affect param")
	}
}

func TestComputeBlindedPubkeyNotHash(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	period := GetTimePeriod(time.Now())
	blinded := ComputeBlindedPubkey(pub, period)
	if len(blinded) != 32 {
		t.Fatal(len(blinded))
	}
	blinded2 := ComputeBlindedPubkey(pub, period)
	if !bytes.Equal(blinded, blinded2) {
		t.Fatal("not deterministic")
	}
	if bytes.Equal(blinded, []byte(pub)) {
		t.Fatal("blinded must differ from identity")
	}
	if _, err := new(edwards25519.Point).SetBytes(blinded); err != nil {
		t.Fatalf("blinded pubkey not a valid ed25519 point: %v %s", err, hex.EncodeToString(blinded))
	}
}

func TestGetTimePeriodMatchesTorFormula(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	got := GetTimePeriod(now)
	minutes := uint64(1700000000) / 60
	want := (minutes - 720) / 1440
	if got != want {
		t.Fatalf("got %d want %d", got, want)
	}
}
