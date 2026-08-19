package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNtorV3OfficialVector 对照 proposal 332 / 现行 spec 的 Python 参考向量。
func TestNtorV3OfficialVector(t *testing.T) {
	b := mustHex(t, "4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a")
	B := mustHex(t, "f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d")
	id := mustHex(t, "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2")
	x := mustHex(t, "b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49")
	X := mustHex(t, "252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f46")
	cm := mustHex(t, "68656c6c6f20776f726c64")
	ver := mustHex(t, "78797a7a79")
	Y := mustHex(t, "4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d")
	sm := mustHex(t, "486f6c61204d756e646f")

	wantEncK1 := mustHex(t, "4cd166e93f1c60a29f8fb9ec40ea0fc878930c27800594593e1c4d0f3b5fbd02")
	wantMacK1 := mustHex(t, "f5b69e85fdd26e1b0bdbbc8128e32d8123040255f11f744af3cc98fc13613cda")
	wantMsgMAC := mustHex(t, "9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")
	wantKeySeed := mustHex(t, "b9a092741098e1f5b8ab37ce74399dd57522c974d7ae4626283a1077b9273255")
	wantVerify := mustHex(t, "1dc09fb249738a79f1bc3a545eee8c415f27213894a760bb4df58862e414799a")
	wantEncKey := mustHex(t, "cab8a93eef62246a83536c4384f331ec26061b66098c61421b6cae81f4f57c56")
	wantAUTH := mustHex(t, "2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a9127665")
	wantClient := mustHex(t, "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")
	wantServer := mustHex(t, "4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c")

	var pubB [32]byte
	var privB [32]byte
	copy(privB[:], b)
	curve25519.ScalarBaseMult(&pubB, &privB)
	if !bytes.Equal(pubB[:], B) {
		t.Fatalf("B from b mismatch")
	}

	skin, st, err := ntorV3ClientHandshakeWithKey(id, B, ver, cm, x)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.X[:], X) {
		t.Fatalf("X mismatch\n got %x\nwant %x", st.X[:], X)
	}

	// 重算 phase1 中间值，定位与向量的差异。
	phase1 := append([]byte(nil), st.Bx[:]...)
	phase1 = append(phase1, id...)
	phase1 = append(phase1, st.X[:]...)
	phase1 = append(phase1, B...)
	phase1 = append(phase1, ntorV3ProtoID...)
	phase1 = append(phase1, ntorV3Encap(ver)...)
	keys := ntorV3KDF(ntorV3TMsgKDF, phase1, 64)
	if !bytes.Equal(keys[:32], wantEncK1) {
		t.Fatalf("ENC_K1 mismatch\n got %x\nwant %x", keys[:32], wantEncK1)
	}
	if !bytes.Equal(keys[32:], wantMacK1) {
		t.Fatalf("MAC_K1 mismatch\n got %x\nwant %x", keys[32:], wantMacK1)
	}
	if !bytes.Equal(st.msgMAC, wantMsgMAC) {
		t.Fatalf("msg_mac mismatch\n got %x\nwant %x", st.msgMAC, wantMsgMAC)
	}
	if !bytes.Equal(skin, wantClient) {
		t.Fatalf("client handshake mismatch\n got %x\nwant %x", skin, wantClient)
	}

	km, gotSM, err := NtorV3ProcessResponse(wantServer, st, ver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSM, sm) {
		t.Fatalf("SM mismatch\n got %x\nwant %x", gotSM, sm)
	}
	if len(km) != NtorV3KeyMaterialLen {
		t.Fatalf("key material len %d", len(km))
	}

	// 校验中间 key_seed / verify / ENC_KEY / AUTH（服务端回复已含 AUTH）
	var Yx [32]byte
	var xArr, Yarr [32]byte
	copy(xArr[:], x)
	copy(Yarr[:], Y)
	curve25519.ScalarMult(&Yx, &xArr, &Yarr)
	secret := append([]byte(nil), Yx[:]...)
	secret = append(secret, st.Bx[:]...)
	secret = append(secret, id...)
	secret = append(secret, B...)
	secret = append(secret, st.X[:]...)
	secret = append(secret, Y...)
	secret = append(secret, ntorV3ProtoID...)
	secret = append(secret, ntorV3Encap(ver)...)
	if got := ntorV3Hash(ntorV3TKeySeed, secret); !bytes.Equal(got, wantKeySeed) {
		t.Fatalf("key_seed mismatch\n got %x\nwant %x", got, wantKeySeed)
	}
	if got := ntorV3Hash(ntorV3TVerify, secret); !bytes.Equal(got, wantVerify) {
		t.Fatalf("verify mismatch\n got %x\nwant %x", got, wantVerify)
	}
	raw := ntorV3KDF(ntorV3TFinal, wantKeySeed, 32+72)
	if !bytes.Equal(raw[:32], wantEncKey) {
		t.Fatalf("ENC_KEY mismatch\n got %x\nwant %x", raw[:32], wantEncKey)
	}
	if !bytes.Equal(wantServer[32:64], wantAUTH) {
		t.Fatal("vector AUTH field mismatch")
	}
}

func TestNtorV3ExtensionsRoundTrip(t *testing.T) {
	raw := EncodeCCRequest()
	if len(raw) != 3 || raw[0] != 1 || raw[1] != NtorV3ExtCCRequest || raw[2] != 0 {
		t.Fatalf("CC request encoding: %x", raw)
	}
	exts, err := ParseNtorV3Extensions(raw)
	if err != nil || len(exts) != 1 || exts[0].Type != NtorV3ExtCCRequest {
		t.Fatalf("parse CC request: %v %#v", err, exts)
	}

	empty := EncodeNtorV3Extensions(nil)
	if _, err := ParseNtorV3Extensions(empty); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNtorV3Extensions(nil); err == nil {
		t.Fatal("empty extra data must fail")
	}

	sm := EncodeNtorV3Extensions([]NtorV3Extension{{Type: NtorV3ExtCCResponse, Data: []byte{31}}})
	inc, ok, err := ParseCCSendmeInc(sm)
	if err != nil || !ok || inc != 31 {
		t.Fatalf("sendme_inc: inc=%d ok=%v err=%v", inc, ok, err)
	}
}

func TestNtorV3RejectsZeroKeys(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 32)
	onion := bytes.Repeat([]byte{2}, 32)
	if _, _, err := NtorV3ClientHandshake(make([]byte, 32), onion, nil, EncodeNtorV3Extensions(nil)); err == nil {
		t.Fatal("zero identity must fail")
	}
	if _, _, err := NtorV3ClientHandshake(id, make([]byte, 32), nil, EncodeNtorV3Extensions(nil)); err == nil {
		t.Fatal("zero onion key must fail")
	}
	if _, _, err := NtorV3ClientHandshake(id[:20], onion, nil, EncodeNtorV3Extensions(nil)); err == nil {
		t.Fatal("RSA-length ID must fail")
	}
}
