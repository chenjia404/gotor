package onion

import (
	"testing"
)

func TestBuildVerifyEstablishIntro(t *testing.T) {
	keys, err := GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 20)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	payload, err := BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != 0x02 {
		t.Fatalf("AUTH_KEY_TYPE=%d", payload[0])
	}
	if err := VerifyEstablishIntroPayload(payload, nonce); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), nonce...)
	bad[0] ^= 0xff
	if err := VerifyEstablishIntroPayload(payload, bad); err == nil {
		t.Fatal("expected MAC failure")
	}
}

func TestEstablishIntroDoSExtensionRoundTrip(t *testing.T) {
	keys, err := GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 20)
	payload, err := BuildEstablishIntroPayloadWithDoS(keys.AuthPublic, keys.AuthPrivate, nonce, 25, 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEstablishIntroPayload(payload, nonce); err != nil {
		t.Fatal(err)
	}
	ext := ParseEstablishIntroDoSExtension(payload)
	if !ext.Present || ext.Rate != 25 || ext.Burst != 200 {
		t.Fatalf("dos ext %+v", ext)
	}
	def := IntroDoSParamsFromConsensus(nil)
	if def.Defense || def.Rate != 25 || def.Burst != 200 {
		t.Fatalf("consensus default %+v", def)
	}
	got := IntroDoSParamsFromConsensus(map[string]int{
		"HiddenServiceEnableIntroDoSDefense":     1,
		"HiddenServiceEnableIntroDoSRatePerSec":  -3,
		"HiddenServiceEnableIntroDoSBurstPerSec": 1 << 31,
	})
	if !got.Defense || got.Rate != 0 || got.Burst != introDoSMax {
		t.Fatalf("clamp %+v", got)
	}
	off := ResolveIntroDoS(IntroDoSExtension{Present: true, Rate: 0, Burst: 200}, got)
	if off.Defense {
		t.Fatal("rate 0 must disable")
	}
	on := IntroDoSParams{Defense: true, Rate: 25, Burst: 200}
	ignored := ResolveIntroDoS(IntroDoSExtension{Present: true, Rate: 50, Burst: 10}, on)
	if !ignored.Defense || ignored.Rate != 25 || ignored.Burst != 200 {
		t.Fatalf("burst<rate should fall back, got %+v", ignored)
	}
}

func TestEstablishIntroRejectsBadTypeWidth(t *testing.T) {
	// 旧错误实现用 2 字节 AUTH_KEY_TYPE — 确保新格式为 1 字节
	keys, err := GenerateEstablishIntroKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 20)
	payload, err := BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, nonce)
	if err != nil {
		t.Fatal(err)
	}
	// AUTH_KEY_LEN 在 offset 1..2
	if payload[1] != 0x00 || payload[2] != 0x20 {
		t.Fatalf("AUTH_KEY_LEN bytes %x %x", payload[1], payload[2])
	}
}
