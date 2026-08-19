package crypto

import (
	"bytes"
	"testing"
)

func TestPolyvalRFC8452(t *testing.T) {
	// RFC 8452 Appendix A
	h := mustHex(t, "25629347589242761d31f826ba4b757b")
	x1 := mustHex(t, "4f4f95668c83dfb6401762bb2d01a262")
	x2 := mustHex(t, "d1a24ddd2721d006bbe45f20d3c9f362")
	want := mustHex(t, "f7a3b47b846119fae5b7866cf5e5b77e")
	data := append(x1, x2...)
	got := polyval(h, data)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("POLYVAL RFC8452\n got %x\nwant %x", got, want)
	}
}

func TestPolyvalZeroTweakAESZero(t *testing.T) {
	// UH(0, 510 zeros) 必须是 0，这样 ET 全零加密就是 AES-ECB(0)=66e94bd4...
	h := make([]byte, 16)
	tweak := make([]byte, 510)
	got := polyval(h, tweak)
	if !bytes.Equal(got[:], make([]byte, 16)) {
		t.Fatalf("POLYVAL(0, 510 zeros)=%x", got)
	}
}
