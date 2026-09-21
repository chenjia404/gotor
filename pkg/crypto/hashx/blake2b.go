package hashx

import (
	"encoding/binary"
	"math/bits"
)

// blake2bHashX 计算 HashX 种子用的 Blake2b-512：盐为 "HashX v1"，无个性化、无密钥。
func blake2bHashX(data []byte) [64]byte {
	h := [8]uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	h[0] ^= 64 | (1 << 16) | (1 << 24)
	var salt [8]byte
	copy(salt[:], hashxPerson)
	h[4] ^= binary.LittleEndian.Uint64(salt[:])

	var c [2]uint64
	var sum [64]byte
	if length := len(data); length > 128 {
		n := length &^ 127
		if length == n {
			n -= 128
		}
		hashBlocks(&h, &c, 0, data[:n])
		data = data[n:]
	}
	var block [128]byte
	offset := copy(block[:], data)
	remaining := uint64(128 - offset) // #nosec G115 -- offset 由 copy 得到，0..128
	if c[0] < remaining {
		c[1]--
	}
	c[0] -= remaining
	hashBlocks(&h, &c, 0xFFFFFFFFFFFFFFFF, block[:])
	for i, v := range h {
		binary.LittleEndian.PutUint64(sum[8*i:], v)
	}
	return sum
}

var blake2bSigma = [12][16]byte{
	{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
	{14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
	{11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4},
	{7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8},
	{9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13},
	{2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9},
	{12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11},
	{13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10},
	{6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5},
	{10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0},
	{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
	{14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
}

func hashBlocks(h *[8]uint64, c *[2]uint64, flag uint64, blocks []byte) {
	iv0, iv1, iv2, iv3 := uint64(0x6a09e667f3bcc908), uint64(0xbb67ae8584caa73b), uint64(0x3c6ef372fe94f82b), uint64(0xa54ff53a5f1d36f1)
	iv4, iv5, iv6, iv7 := uint64(0x510e527fade682d1), uint64(0x9b05688c2b3e6c1f), uint64(0x1f83d9abfb41bd6b), uint64(0x5be0cd19137e2179)
	var m [16]uint64
	c0, c1 := c[0], c[1]
	for i := 0; i < len(blocks); {
		c0 += 128
		if c0 < 128 {
			c1++
		}
		v0, v1, v2, v3, v4, v5, v6, v7 := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		v8, v9, v10, v11, v12, v13, v14, v15 := iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7
		v12 ^= c0
		v13 ^= c1
		v14 ^= flag
		for j := range m {
			m[j] = binary.LittleEndian.Uint64(blocks[i:])
			i += 8
		}
		for j := range blake2bSigma {
			s := &blake2bSigma[j]
			v0 += m[s[0]]
			v0 += v4
			v12 ^= v0
			v12 = bits.RotateLeft64(v12, -32)
			v8 += v12
			v4 ^= v8
			v4 = bits.RotateLeft64(v4, -24)
			v1 += m[s[1]]
			v1 += v5
			v13 ^= v1
			v13 = bits.RotateLeft64(v13, -32)
			v9 += v13
			v5 ^= v9
			v5 = bits.RotateLeft64(v5, -24)
			v2 += m[s[2]]
			v2 += v6
			v14 ^= v2
			v14 = bits.RotateLeft64(v14, -32)
			v10 += v14
			v6 ^= v10
			v6 = bits.RotateLeft64(v6, -24)
			v3 += m[s[3]]
			v3 += v7
			v15 ^= v3
			v15 = bits.RotateLeft64(v15, -32)
			v11 += v15
			v7 ^= v11
			v7 = bits.RotateLeft64(v7, -24)

			v0 += m[s[4]]
			v0 += v4
			v12 ^= v0
			v12 = bits.RotateLeft64(v12, -16)
			v8 += v12
			v4 ^= v8
			v4 = bits.RotateLeft64(v4, -63)
			v1 += m[s[5]]
			v1 += v5
			v13 ^= v1
			v13 = bits.RotateLeft64(v13, -16)
			v9 += v13
			v5 ^= v9
			v5 = bits.RotateLeft64(v5, -63)
			v2 += m[s[6]]
			v2 += v6
			v14 ^= v2
			v14 = bits.RotateLeft64(v14, -16)
			v10 += v14
			v6 ^= v10
			v6 = bits.RotateLeft64(v6, -63)
			v3 += m[s[7]]
			v3 += v7
			v15 ^= v3
			v15 = bits.RotateLeft64(v15, -16)
			v11 += v15
			v7 ^= v11
			v7 = bits.RotateLeft64(v7, -63)

			v0 += m[s[8]]
			v0 += v5
			v15 ^= v0
			v15 = bits.RotateLeft64(v15, -32)
			v10 += v15
			v5 ^= v10
			v5 = bits.RotateLeft64(v5, -24)
			v1 += m[s[9]]
			v1 += v6
			v12 ^= v1
			v12 = bits.RotateLeft64(v12, -32)
			v11 += v12
			v6 ^= v11
			v6 = bits.RotateLeft64(v6, -24)
			v2 += m[s[10]]
			v2 += v7
			v13 ^= v2
			v13 = bits.RotateLeft64(v13, -32)
			v8 += v13
			v7 ^= v8
			v7 = bits.RotateLeft64(v7, -24)
			v3 += m[s[11]]
			v3 += v4
			v14 ^= v3
			v14 = bits.RotateLeft64(v14, -32)
			v9 += v14
			v4 ^= v9
			v4 = bits.RotateLeft64(v4, -24)

			v0 += m[s[12]]
			v0 += v5
			v15 ^= v0
			v15 = bits.RotateLeft64(v15, -16)
			v10 += v15
			v5 ^= v10
			v5 = bits.RotateLeft64(v5, -63)
			v1 += m[s[13]]
			v1 += v6
			v12 ^= v1
			v12 = bits.RotateLeft64(v12, -16)
			v11 += v12
			v6 ^= v11
			v6 = bits.RotateLeft64(v6, -63)
			v2 += m[s[14]]
			v2 += v7
			v13 ^= v2
			v13 = bits.RotateLeft64(v13, -16)
			v8 += v13
			v7 ^= v8
			v7 = bits.RotateLeft64(v7, -63)
			v3 += m[s[15]]
			v3 += v4
			v14 ^= v3
			v14 = bits.RotateLeft64(v14, -16)
			v9 += v14
			v4 ^= v9
			v4 = bits.RotateLeft64(v4, -63)
		}
		h[0] ^= v0 ^ v8
		h[1] ^= v1 ^ v9
		h[2] ^= v2 ^ v10
		h[3] ^= v3 ^ v11
		h[4] ^= v4 ^ v12
		h[5] ^= v5 ^ v13
		h[6] ^= v6 ^ v14
		h[7] ^= v7 ^ v15
	}
	c[0], c[1] = c0, c1
}
