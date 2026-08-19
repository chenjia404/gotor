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
