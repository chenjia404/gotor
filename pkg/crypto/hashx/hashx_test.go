package hashx

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSipRoundPaper(t *testing.T) {
	s := sipState{
		v0: 0x7469686173716475,
		v1: 0x6b617f6d656e6665,
		v2: 0x6b7f62616d677361,
		v3: 0x7c6d6c6a717c6d7b,
	}
	s.sipRound()
	s.sipRound()
	if s.v0 != 0x4d07749cdd0858e0 || s.v1 != 0x0d52f6f62a4f59a4 ||
		s.v2 != 0x634cb3577b01fd3d || s.v3 != 0xa5224d6f55c7d9c8 {
		t.Fatalf("sip_round 向量不符: %+v", s)
	}
}

func TestPairFromSeed(t *testing.T) {
	k0, k1 := pairFromSeed([]byte{})
	if k0.v0 != 0xcaca7747b3c5be92 || k0.v1 != 0x296abd268b5f21de ||
		k0.v2 != 0x9e4c4d2f95add72a || k0.v3 != 0x00ac7f27331ec1c7 {
		d := blake2bHashX(nil)
		t.Fatalf("空种子 key0=%+v digest=%x", k0, d[:])
	}
	if k1.v0 != 0xc32d197f86f1c419 || k1.v1 != 0xbbe47abaf4e28dfe ||
		k1.v2 != 0xc174b9d5786f28d4 || k1.v3 != 0xa2bd4197b22a035a {
		t.Fatalf("空种子 key1=%+v", k1)
	}

	k0, k1 = pairFromSeed([]byte("abc"))
	if k0.v0 != 0xc538fa793ed99a50 || k0.v1 != 0xd2fd3e8871310ea1 ||
		k0.v2 != 0xd2be7d8aff1f823a || k0.v3 != 0x557b84887cfe6c0e {
		t.Fatalf("abc key0=%+v", k0)
	}
	if k1.v0 != 0x610218b2104c3f5a || k1.v1 != 0x4222e8a58e702331 ||
		k1.v2 != 0x0d53a2563a33148d || k1.v3 != 0x7c24f97da4bff21f {
		t.Fatalf("abc key1=%+v", k1)
	}
}

func TestSiphash24Ctr(t *testing.T) {
	_, key1 := pairFromSeed([]byte("abc"))
	got := siphash24Ctr(key1, 0)
	want := [8]uint64{
		0xe8a59a4b3ccb5e4a, 0xe45153f8bb93540d, 0x32c6accb77141596, 0xd5deaa56a3b1cfd7,
		0xc5f6ff8435b80af4, 0xd26fd3ccfdf2a04f, 0x3d7fa0f14653348e, 0xf5a4750be0aa2ccf,
	}
	if got != want {
		t.Fatalf("ctr0=%v want %v", got, want)
	}
	got = siphash24Ctr(key1, 999)
	want = [8]uint64{
		0x312470a168998148, 0xc9624473753e8d0e, 0xc0879d8f0de37dbf, 0xfa4cc48f4f6e95d5,
		0x9940dc39eaaceb2c, 0x29143feae886f221, 0x98f119184c4cffe5, 0xcf1571c6d0d18131,
	}
	if got != want {
		t.Fatalf("ctr999=%v want %v", got, want)
	}
}

func TestRngVectors(t *testing.T) {
	key0, _ := pairFromSeed([]byte("abc"))
	rng := newSipRand(key0)
	buf := newRngBuffer(rng.nextU64)
	type kind int
	const (
		kU32 kind = iota
		kU8
	)
	expected := []struct {
		k kind
		v uint32
	}{
		{kU32, 0xf695edd0}, {kU32, 0x2205449d}, {kU32, 0x51c1ac51}, {kU32, 0xcd19a7d1},
		{kU8, 0xad}, {kU32, 0x79793a52}, {kU32, 0xd965083d}, {kU8, 0xf4},
		{kU32, 0x915e9969}, {kU32, 0x7563b6e2}, {kU32, 0x4e5a9d8b}, {kU32, 0xef2bb9ce},
		{kU8, 0xcb}, {kU32, 0xa4beee16}, {kU32, 0x78fa6e6f}, {kU8, 0x30},
		{kU32, 0xc321cb9f}, {kU32, 0xbbf29635}, {kU32, 0x919450f4}, {kU32, 0xf3d8f358},
		{kU8, 0x3b}, {kU32, 0x818a72e9}, {kU32, 0x58225fcf}, {kU8, 0x98},
		{kU32, 0x3fcb5059}, {kU32, 0xaf5bcb70}, {kU8, 0x14}, {kU32, 0xd41e0326},
		{kU32, 0xe79aebc6}, {kU32, 0xa348672c}, {kU8, 0xcf}, {kU32, 0x5d51b520},
		{kU32, 0x73afc36f}, {kU32, 0x31348711}, {kU32, 0xca25b040}, {kU32, 0x3700c37b},
		{kU8, 0x62}, {kU32, 0xf0d1d6a6}, {kU32, 0xc1edebf3}, {kU8, 0x9d},
		{kU32, 0x9bb1f33f}, {kU32, 0xf1309c95}, {kU32, 0x0797718a}, {kU32, 0xa3bbcf7e},
		{kU8, 0x80}, {kU8, 0x28}, {kU8, 0xe9}, {kU8, 0x2e}, {kU32, 0xf5506289},
		{kU32, 0x97b46d7c}, {kU8, 0x64}, {kU32, 0xc99fe4ad}, {kU32, 0x6e756189},
		{kU8, 0x54}, {kU8, 0xf7}, {kU8, 0x0f}, {kU8, 0x7d}, {kU32, 0x38c983eb},
	}
	for i, e := range expected {
		if e.k == kU8 {
			got := buf.nextU8()
			if uint32(got) != e.v {
				t.Fatalf("rng[%d] u8=0x%02x want 0x%02x", i, got, e.v)
			}
		} else {
			got := buf.nextU32()
			if got != e.v {
				t.Fatalf("rng[%d] u32=0x%08x want 0x%08x", i, got, e.v)
			}
		}
	}
}

func mustHash(t *testing.T, seed []byte) *HashX {
	t.Helper()
	h, err := New(seed)
	if err != nil {
		t.Fatalf("HashX.New: %v", err)
	}
	return h
}

func TestHashXSeed1(t *testing.T) {
	h := mustHash(t, append([]byte("This is a test"), 0))
	if h.HashToU64(0) != 0x98eacb7d56542f2b {
		t.Fatalf("hash_u64(0)=%#x", h.HashToU64(0))
	}
	if h.HashToU64(123456) != 0xaf937ca60ad5bdae {
		t.Fatalf("hash_u64(123456)=%#x", h.HashToU64(123456))
	}
	want0, _ := hex.DecodeString("2b2f54567dcbea98fdb5d5e5ce9a65983c4a4e35ab1464b1efb61e83b7074bb2")
	got0 := h.HashToBytes(0)
	if !bytes.Equal(got0[:], want0) {
		t.Fatalf("bytes(0)=%x want %x", got0, want0)
	}
	want1, _ := hex.DecodeString("aebdd50aa67c93afb82a4c534603b65e46decd584c55161c526ebc099415ccf1")
	got1 := h.HashToBytes(123456)
	if !bytes.Equal(got1[:], want1) {
		t.Fatalf("bytes(123456)=%x want %x", got1, want1)
	}
}

func TestHashXSeed2(t *testing.T) {
	h := mustHash(t, append([]byte("Lorem ipsum dolor sit amet"), 0))
	if h.HashToU64(123456) != 0xaab0bbf45b153dab {
		t.Fatalf("hash_u64(123456)=%#x", h.HashToU64(123456))
	}
	if h.HashToU64(987654321123456789) != 0x7432327c49f0fe8d {
		t.Fatalf("hash_u64(big)=%#x", h.HashToU64(987654321123456789))
	}
}

func TestHashXBadSeeds(t *testing.T) {
	if _, err := New([]byte{0xf8, 0x05, 0x00, 0x00}); err != nil {
		t.Fatalf("控制种子应成功: %v", err)
	}
	if _, err := New([]byte{0xf9, 0x05, 0x00, 0x00}); err == nil {
		t.Fatal("期望 ProgramConstraints")
	}
	if _, err := New([]byte{0x5d, 0x93, 0x02, 0x00}); err == nil {
		t.Fatal("期望 ProgramConstraints")
	}
	if _, err := New([]byte{0x5e, 0x93, 0x02, 0x00}); err != nil {
		t.Fatalf("控制种子应成功: %v", err)
	}
}
