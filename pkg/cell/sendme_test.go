package cell

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeSendmeV1(t *testing.T) {
	digest := bytesRepeat(0xab, 20)
	payload, err := EncodeSendmeV1(digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 23 {
		t.Fatalf("payload len %d, want 23", len(payload))
	}
	if payload[0] != SendmeVersion1 {
		t.Fatalf("version %d", payload[0])
	}
	ver, got, err := DecodeSendme(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ver != SendmeVersion1 {
		t.Fatalf("decoded version %d", ver)
	}
	if !bytes.Equal(got, digest) {
		t.Fatalf("digest mismatch")
	}
}

func TestDecodeSendmeEmptyIsV0(t *testing.T) {
	ver, digest, err := DecodeSendme(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ver != SendmeVersion0 || digest != nil {
		t.Fatalf("empty payload must be v0, got ver=%d digest=%v", ver, digest)
	}
}

func TestEncodeSendmeV1RejectsWrongLength(t *testing.T) {
	if _, err := EncodeSendmeV1([]byte("short")); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeSendmeV1ShortDigest(t *testing.T) {
	payload := []byte{0x01, 0x00, 0x04, 1, 2, 3, 4}
	if _, _, err := DecodeSendme(payload); err == nil {
		t.Fatal("expected error for DATA_LEN < 20")
	}
}

func TestDecodeSendmeUnknownVersion(t *testing.T) {
	payload := []byte{0x09, 0x00, 0x00}
	if _, _, err := DecodeSendme(payload); err == nil {
		t.Fatal("expected error for unrecognized version")
	}
}

func TestDecodeSendmeV1IgnoresExtraBytes(t *testing.T) {
	digest := bytesRepeat(0x11, 20)
	payload, err := EncodeSendmeV1(digest)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, 0xaa, 0xbb)
	ver, got, err := DecodeSendme(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ver != SendmeVersion1 || !bytes.Equal(got, digest) {
		t.Fatal("extra bytes after 20-byte digest must be ignored")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
