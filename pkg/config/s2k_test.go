package config

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashControlPasswordKnownVector(t *testing.T) {
	// control-spec 示例：password "foo"
	salt, err := hex.DecodeString("660537E3E1CD4999")
	if err != nil {
		t.Fatal(err)
	}
	got, err := HashControlPasswordWithSalt("foo", salt, 0x60)
	if err != nil {
		t.Fatal(err)
	}
	want := "16:660537E3E1CD49996044A3BF558097A981F539FEA2F9DA662B4626C1C2"
	if !strings.EqualFold(got, want) {
		t.Fatalf("got %s want %s", got, want)
	}
	if !VerifyHashedControlPassword("foo", want) {
		t.Fatal("verify foo failed")
	}
	if VerifyHashedControlPassword("bar", want) {
		t.Fatal("bar must not verify")
	}
}

func TestHashControlPasswordRoundTrip(t *testing.T) {
	h, err := HashControlPassword("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "16:") {
		t.Fatalf("prefix: %s", h)
	}
	if !VerifyHashedControlPassword("secret-pass", h) {
		t.Fatal("round-trip verify failed")
	}
}
