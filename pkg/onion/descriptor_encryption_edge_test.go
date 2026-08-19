package onion

import (
	"testing"
)

func TestDecryptDescriptorEdgeCases(t *testing.T) {
	pub := make([]byte, 32)
	pub[0] = 1
	addr := &Address{Pubkey: pub, Version: 3}

	t.Run("nil descriptor", func(t *testing.T) {
		if _, err := DecryptDescriptor(nil, addr, 1); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("nil address", func(t *testing.T) {
		if _, err := DecryptDescriptor(&Descriptor{RawDescriptor: []byte("x")}, nil, 1); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("short pubkey", func(t *testing.T) {
		if _, err := DecryptDescriptor(&Descriptor{}, &Address{Pubkey: make([]byte, 16)}, 1); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing superencrypted", func(t *testing.T) {
		d := &Descriptor{RawDescriptor: []byte("hs-descriptor 3\nrevision-counter 1\n")}
		if _, err := DecryptDescriptor(d, addr, 1); err == nil {
			t.Fatal("expected error when no intro points and no superencrypted")
		}
	})
	t.Run("plaintext intro points without encryption", func(t *testing.T) {
		d := &Descriptor{RawDescriptor: []byte("hs-descriptor 3\nintroduction-point a\n"), IntroPoints: []IntroductionPoint{{}}}
		out, err := DecryptDescriptor(d, addr, 1)
		if err != nil {
			t.Fatal(err)
		}
		if out == nil {
			t.Fatal("nil out")
		}
	})
}
