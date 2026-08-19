package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestEd25519KeypairFromCurve25519RoundTrip 供后续 AI 复用：
// 权威用 X25519 公钥 + Bit 还原 Ed25519 公钥，必须等于私钥导出值，且能验签。
func TestEd25519KeypairFromCurve25519RoundTrip(t *testing.T) {
	for i := 0; i < 16; i++ {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			t.Fatal(err)
		}
		kp, err := Ed25519KeypairFromCurve25519(priv)
		if err != nil {
			t.Fatalf("keypair: %v", err)
		}
		if kp.SignBit != 0 && kp.SignBit != 1 {
			t.Fatalf("sign bit %d", kp.SignBit)
		}

		xPub, err := X25519PublicFromPrivate(priv)
		if err != nil {
			t.Fatal(err)
		}
		var legacy [32]byte
		copy(legacy[:], priv)
		var legacyPub [32]byte
		curve25519.ScalarBaseMult(&legacyPub, &legacy)
		if !bytes.Equal(xPub, legacyPub[:]) {
			t.Fatal("X25519PublicFromPrivate != ScalarBaseMult")
		}

		recovered, err := Ed25519PublicFromX25519(xPub, kp.SignBit)
		if err != nil {
			t.Fatalf("recover: %v", err)
		}
		if !bytes.Equal(recovered, kp.Public) {
			t.Fatalf("权威还原公钥与私钥导出不一致\npriv=%x\nxpub=%x\nderived=%x\nrecovered=%x\nbit=%d",
				priv, xPub, kp.Public, recovered, kp.SignBit)
		}

		msg := []byte("ntor-onion-key-crosscert test")
		sig, err := kp.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(recovered, msg, sig) {
			t.Fatal("签名不能用权威还原的公钥验证")
		}
		if ed25519.Verify(recovered, []byte("tampered"), sig) {
			t.Fatal("篡改消息不应通过")
		}
	}
}

func TestEd25519KeypairFromCurve25519RejectsShortKey(t *testing.T) {
	if _, err := Ed25519KeypairFromCurve25519([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Ed25519PublicFromX25519([]byte{1}, 0); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Ed25519PublicFromX25519(make([]byte, 32), 2); err == nil {
		t.Fatal("expected invalid sign bit error")
	}
}
