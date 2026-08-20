package crypto

import (
	"bytes"
	"testing"
)

// 下列向量来自 C Tor src/test/cgo_vectors.inc（python 参考实现生成）。
// 不是我们自己重生的。

func TestCGOETZeros(t *testing.T) {
	keys := bytes.Repeat([]byte{0}, 32)
	tweak := bytes.Repeat([]byte{0}, 510)
	block := make([]byte, 16)
	d := etDirFromKeys(t, keys)
	var m [16]byte
	copy(m[:], block)
	if err := d.encET(tprimeFromTweak(tweak), tweak[16], tweak[17:], &m); err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	if !bytes.Equal(m[:], want) {
		t.Fatalf("ET enc zeros\n got %x\nwant %x", m, want)
	}

	copy(m[:], block)
	if err := d.decET(tprimeFromTweak(tweak), tweak[16], tweak[17:], &m); err != nil {
		t.Fatal(err)
	}
	want = mustHex(t, "140f0f1011b5223d79587717ffd9ec3a")
	if !bytes.Equal(m[:], want) {
		t.Fatalf("ET dec zeros\n got %x\nwant %x", m, want)
	}
}

func TestCGOETPseudorandom1(t *testing.T) {
	keys := mustHex(t, "39dd87e0b958cec5d2ba04a17fad9f134770f20f14038bdcd751056a7f16041f")
	tweak := mustHex(t, "fbf69df9bfc3bec7e4a5dd0c9785dd18727dab2b11baf2898b3b775baed777d209812a71e8d5a1f624a4c2c3ccd91064f494f5deb2b7ab362cda53df3e0291cc439052a05cdbc8fe259f7190792b637eeaf0c5ebdf7d02ec6b89beecf131a916f5c6989267e28defaa5937b35f0a1ce1ef91838c408b2d199170f29e76ae21b8b62a733e4de9d281e6935d20d991e3e1801907f6477f9fd40bd4e72de681336e603bb7ec17d512728864b7cebc9bc6bbc0629082830fa3702cb2eff0fb289b7431d4e1b0b6109599c91c4c78540792331e592fe8c0c190ea18275386ec3d85f68996b6891e484ad4b0601008ead6ed60145f8d01b81d1cf31556744b1676f6c5caea56c5cd424350e0bc3c478efc2e11d868ddf73185627c778ba8b7d684f3d0b9dfe7e1b63985bb43e37a2e5938cae8b1741cb58aea2b383de9bf0531e344a5651f7f145aad1656e695e30ee6483b5e18e43b0aa6e308f2e1c8cfdd85a118476c9ca91c8ca993563b2df014289738c4b6ce772e2ac36a26547b97ba26673e28e634f88a91007e220f1beaa97ae00972954fc705de30642014fa5c4c07792a0f0b4a8ef3c6f0584b1029171a28cd5898e760c91f71c5f9610747ae21f30f1b1bfa7e4df9aedfa8b006f29e89e5b182ac9957067f86767ed5620abcb2c50a41c423e48a676864a2d151c5bf2442f3b90bfd7c047f92cd112367d0579c9f02")
	mIn := mustHex(t, "40f417ba5a4c78a23e6540b52b68e1e6")
	d := etDirFromKeys(t, keys)
	var m [16]byte
	copy(m[:], mIn)
	if err := d.encET(tprimeFromTweak(tweak), tweak[16], tweak[17:], &m); err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "84bfff8347889f1a9f2cf930c82677be")
	if !bytes.Equal(m[:], want) {
		t.Fatalf("ET enc pr1\n got %x\nwant %x", m, want)
	}
	copy(m[:], mIn)
	if err := d.decET(tprimeFromTweak(tweak), tweak[16], tweak[17:], &m); err != nil {
		t.Fatal(err)
	}
	want = mustHex(t, "e2c0bfdef28b5504cf0ec708a6866a17")
	if !bytes.Equal(m[:], want) {
		t.Fatalf("ET dec pr1\n got %x\nwant %x", m, want)
	}
}

func TestCGOPRFZeros(t *testing.T) {
	d := etDirFromKeys(t, bytes.Repeat([]byte{0}, 32))
	// PRF 用同一 32 字节当作 (K,B)
	d.prfK = bytes.Repeat([]byte{0}, 16)
	d.prfB = bytes.Repeat([]byte{0}, 16)
	var t0 [16]byte
	out, err := d.prfCTR(t0, 0, 493)
	if err != nil {
		t.Fatal(err)
	}
	want0 := mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d527029195b84d1b96c690ff2f2de30bf2ec89e00253786e126504f0dab90c48a30321de3345e6b0461e7c9e6c6b7afedde83f40deb3fa6794f8fd8f55a88dcbda9d68f2137cc9c83420077e7cf28ab2696b0df05d11452b58ac50aa2eb3a195b61b87e5c65a6dd5d7f7a84065d5a17ff46273086002496db63fa4b91bee387fa3030c95a73f8d0437e0915fbce5d7a62d8dab0a58b2431bc0bede02550f40238969ec780410befccde6944b69dd007debe39a9dbc5e24f519a4bdf478b1d9ec0b67125f28b06efaa55d79412ad628d45089c3c304f94db3a21df6cdaf6d2e2e3b355441eff64ad90527e752a4b2ebb4d0a1070ce2e2982e272fdb7cf4b584b095a0f957fdb828689437e37dc48b2ad379c6f3c6e957ee77afb88c65949ba12eec45c22865e4907ae42aee813898acdf91e2e4c21d828e0a76de2bb6bb6f869e5eef1f618dedd27562812b9a14e8996a5c352df3817e60d6ec20119a52c80a61ec195622627240212decca515feab63e2734587948a836a7de205cfec0c288351c")
	if !bytes.Equal(out, want0) {
		t.Fatalf("PRF t=0 zeros mismatch first32 got %x want %x", out[:32], want0[:32])
	}
	out1, err := d.prfCTR(t0, 1, 80)
	if err != nil {
		t.Fatal(err)
	}
	want1 := mustHex(t, "7941dd0a63d994703e63d94a446804213ab4fb1d2b7ba376590a2c241d1f508dc6a7f418a14503deb89b17aadb2806f73fc06e5d14e675f5ec880023d4f7329612dce4a0e5bc792b5b5a55f9c2f30e07")
	if !bytes.Equal(out1, want1) {
		t.Fatalf("PRF t=1 zeros\n got %x\nwant %x", out1, want1)
	}
}

func TestCGOUIVZeros(t *testing.T) {
	keys := bytes.Repeat([]byte{0}, 64)
	d, err := newCGODir(append(keys, bytes.Repeat([]byte{0}, 16)...), false)
	if err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CGOMsgLen)
	if err := d.encUIV(0, cell); err != nil {
		t.Fatal(err)
	}
	wantL := mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	if !bytes.Equal(cell[:16], wantL) {
		t.Fatalf("UIV enc Y_L %x want %x", cell[:16], wantL)
	}
	wantR := mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a")
	if !bytes.Equal(cell[16:48], wantR) {
		t.Fatalf("UIV enc Y_R prefix %x want %x", cell[16:48], wantR)
	}

	d2, err := newCGODir(append(append([]byte{}, keys...), bytes.Repeat([]byte{0}, 16)...), true)
	if err != nil {
		t.Fatal(err)
	}
	cell2 := make([]byte, CGOMsgLen)
	if err := d2.decUIV(0, cell2); err != nil {
		t.Fatal(err)
	}
	wantDL := mustHex(t, "140f0f1011b5223d79587717ffd9ec3a")
	if !bytes.Equal(cell2[:16], wantDL) {
		t.Fatalf("UIV dec Y_L %x want %x", cell2[:16], wantDL)
	}
}

func TestCGOUIVUpdateZeros(t *testing.T) {
	keys := bytes.Repeat([]byte{0}, 64)
	d, err := newCGODir(append(keys, bytes.Repeat([]byte{0}, 16)...), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.updateUIV(); err != nil {
		t.Fatal(err)
	}
	wantK := mustHex(t, "7941dd0a63d994703e63d94a446804213ab4fb1d2b7ba376590a2c241d1f508dc6a7f418a14503deb89b17aadb2806f73fc06e5d14e675f5ec880023d4f73296")
	if !bytes.Equal(d.snapshotKeys(), wantK) {
		t.Fatalf("UPDATE keys\n got %x\nwant %x", d.snapshotKeys(), wantK)
	}
	wantN := mustHex(t, "12dce4a0e5bc792b5b5a55f9c2f30e07")
	if !bytes.Equal(d.nonce[:], wantN) {
		t.Fatalf("UPDATE nonce %x want %x", d.nonce, wantN)
	}
}

func TestCGORelayOriginateZeros(t *testing.T) {
	d, err := newCGODirForTest(bytes.Repeat([]byte{0}, 64), bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{0}, 16), false)
	if err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CGOMsgLen)
	tag, err := d.RelayOriginate(0, cell)
	if err != nil {
		t.Fatal(err)
	}
	wantT := mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	if !bytes.Equal(tag, wantT) || !bytes.Equal(cell[:16], wantT) {
		t.Fatalf("relay originate T %x want %x", tag, wantT)
	}
	wantK := mustHex(t, "7941dd0a63d994703e63d94a446804213ab4fb1d2b7ba376590a2c241d1f508dc6a7f418a14503deb89b17aadb2806f73fc06e5d14e675f5ec880023d4f73296")
	if !bytes.Equal(d.snapshotKeys(), wantK) {
		t.Fatalf("relay originate keys mismatch")
	}
	wantN := mustHex(t, "12dce4a0e5bc792b5b5a55f9c2f30e07")
	if !bytes.Equal(d.nonce[:], wantN) {
		t.Fatalf("relay originate N %x", d.nonce)
	}
}

func TestCGOClientOriginateZerosHop3(t *testing.T) {
	hops := make([]*CGODir, 3)
	for i := range hops {
		d, err := newCGODirForTest(bytes.Repeat([]byte{0}, 64), bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{0}, 16), true)
		if err != nil {
			t.Fatal(err)
		}
		hops[i] = d
	}
	cell := make([]byte, CGOMsgLen)
	_, err := ClientOriginateHops(hops, 2, 0, cell)
	if err != nil {
		t.Fatal(err)
	}
	wantT := mustHex(t, "1471e71e6fb1f04233a8ec5daa6209e0")
	if !bytes.Equal(cell[:16], wantT) {
		t.Fatalf("client originate T %x want %x", cell[:16], wantT)
	}
	wantHop3K := mustHex(t, "7941dd0a63d994703e63d94a446804213ab4fb1d2b7ba376590a2c241d1f508dc6a7f418a14503deb89b17aadb2806f73fc06e5d14e675f5ec880023d4f73296")
	if !bytes.Equal(hops[2].snapshotKeys(), wantHop3K) {
		t.Fatalf("hop3 keys\n got %x\nwant %x", hops[2].snapshotKeys(), wantHop3K)
	}
	wantHop1T := mustHex(t, "af65bb470269ecd7af01f68f1a2b7b78")
	if !bytes.Equal(hops[0].tprime[:], wantHop1T) {
		t.Fatalf("hop1 T' %x want %x", hops[0].tprime, wantHop1T)
	}
	wantHop2T := mustHex(t, "140f0f1011b5223d79587717ffd9ec3a")
	if !bytes.Equal(hops[1].tprime[:], wantHop2T) {
		t.Fatalf("hop2 T' %x want %x", hops[1].tprime, wantHop2T)
	}
}

func TestCGOClientRoundtrip(t *testing.T) {
	keys := bytes.Repeat([]byte{0x11}, CGOKeyMaterialLen)
	pair, err := NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	// 用同一把前向密钥模拟「中继用 ENC、客户端用 DEC」会失败；
	// 这里只验证客户端 originate 后，用同一 Fwd 再 forward 会破坏 recognized。
	// 正确往返：目的跳 originate 后，对端用 RelayForward 识别。
	relay, err := newCGODir(keys[:CGODirKeyLen], false)
	if err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CGOMsgLen)
	copy(cell[16:], bytes.Repeat([]byte{0x42}, 20))
	if _, err := pair.Fwd.ClientOriginate(3, cell); err != nil {
		t.Fatal(err)
	}
	rec, _, err := relay.RelayForward(3, cell)
	if err != nil {
		t.Fatal(err)
	}
	if !rec {
		t.Fatal("relay should recognize client-originated cell")
	}
	if !bytes.Equal(cell[16:36], bytes.Repeat([]byte{0x42}, 20)) {
		t.Fatalf("plaintext body corrupted: %x", cell[16:36])
	}
}

func TestCGOClientBackwardRoundtrip(t *testing.T) {
	keys := bytes.Repeat([]byte{0x22}, CGOKeyMaterialLen)
	pair, err := NewCGOPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newCGODir(keys[CGODirKeyLen:], false)
	if err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CGOMsgLen)
	plain := []byte("extended2-body-here!!")
	copy(cell[16:], plain)
	if _, err := relay.RelayOriginate(3, cell); err != nil {
		t.Fatal(err)
	}
	rec, tag, err := pair.Back.ClientBackward(3, cell)
	if err != nil {
		t.Fatal(err)
	}
	if !rec {
		t.Fatal("client should recognize relay-originated cell")
	}
	if len(tag) != CGOTagLen {
		t.Fatalf("tag len %d", len(tag))
	}
	if !bytes.Equal(cell[16:16+len(plain)], plain) {
		t.Fatalf("plaintext body corrupted: %x", cell[16:16+len(plain)])
	}
}

func TestCGOKeyMaterialLen(t *testing.T) {
	if CGOKeyMaterialLen != 160 {
		t.Fatalf("C Tor relay_crypto_key_material_len(CGO)=160, got %d", CGOKeyMaterialLen)
	}
	if _, err := NewCGOPairFromKeyMaterial(make([]byte, 72)); err == nil {
		t.Fatal("must reject tor1 72-byte material")
	}
	if _, err := NewCGORelayPairFromKeyMaterial(make([]byte, 72)); err == nil {
		t.Fatal("relay pair must reject tor1 72-byte material")
	}
	keys := bytes.Repeat([]byte{0x66}, CGOKeyMaterialLen)
	relay, err := NewCGORelayPairFromKeyMaterial(keys)
	if err != nil {
		t.Fatal(err)
	}
	if relay.Fwd.decrypt || relay.Back.decrypt {
		t.Fatal("中继对必须是 ENC_UIV")
	}
}

func etDirFromKeys(t *testing.T, keys []byte) *CGODir {
	t.Helper()
	d := &CGODir{
		etKB: append([]byte(nil), keys[:16]...),
		etKU: append([]byte(nil), keys[16:32]...),
	}
	if err := d.ensureET(); err != nil {
		t.Fatal(err)
	}
	return d
}

func tprimeFromTweak(tweak []byte) [16]byte {
	var t [16]byte
	copy(t[:], tweak[:16])
	return t
}
