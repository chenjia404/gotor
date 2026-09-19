package circuit

import (
	"bytes"
	"testing"
)

func TestNewHopFromHSKeyMaterialResponderSwapsDirection(t *testing.T) {
	km := bytes.Repeat([]byte{1}, 32)
	km = append(km, bytes.Repeat([]byte{2}, 32)...)
	km = append(km, bytes.Repeat([]byte{3}, 32)...)
	km = append(km, bytes.Repeat([]byte{4}, 32)...)

	client, err := NewHopFromHSKeyMaterial(km)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewHopFromHSKeyMaterialResponder(km)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hs-hop-direction")
	ct := append([]byte(nil), plain...)
	client.ForwardCipher.XORKeyStream(ct, ct)
	got := append([]byte(nil), ct...)
	svc.BackwardCipher.XORKeyStream(got, got)
	if !bytes.Equal(got, plain) {
		t.Fatal("服务端 backward 应解开客户端 forward")
	}
}
