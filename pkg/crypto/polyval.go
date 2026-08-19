package crypto

import (
	"encoding/binary"
	"math/bits"
)

// POLYVAL（RFC 8452）：CGO 的 UH。域 GF(2^128)，多项式
// x^128 + x^127 + x^126 + x^121 + 1。小端输入。
//
// 乘法对照 C Tor src/ext/polyval/ctmul64.c（BearSSL GHASH 变体，去掉 GHASH 专用左移）。

const polyvalBlockLen = 16

func polyval(h, data []byte) [16]byte {
	var y [16]byte
	if len(h) != polyvalBlockLen {
		return y
	}
	hLo := binary.LittleEndian.Uint64(h[:8])
	hHi := binary.LittleEndian.Uint64(h[8:])
	yLo := uint64(0)
	yHi := uint64(0)

	for off := 0; off < len(data); {
		var blk [16]byte
		n := copy(blk[:], data[off:])
		off += n
		if n == 0 {
			break
		}
		yLo ^= binary.LittleEndian.Uint64(blk[:8])
		yHi ^= binary.LittleEndian.Uint64(blk[8:])
		yLo, yHi = polyvalMul64(yLo, yHi, hLo, hHi)
	}
	binary.LittleEndian.PutUint64(y[:8], yLo)
	binary.LittleEndian.PutUint64(y[8:], yHi)
	return y
}

func bmul64(x, y uint64) uint64 {
	x0 := x & 0x1111111111111111
	x1 := x & 0x2222222222222222
	x2 := x & 0x4444444444444444
	x3 := x & 0x8888888888888888
	y0 := y & 0x1111111111111111
	y1 := y & 0x2222222222222222
	y2 := y & 0x4444444444444444
	y3 := y & 0x8888888888888888
	z0 := (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
	z1 := (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
	z2 := (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
	z3 := (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
	z0 &= 0x1111111111111111
	z1 &= 0x2222222222222222
	z2 &= 0x4444444444444444
	z3 &= 0x8888888888888888
	return z0 | z1 | z2 | z3
}

func polyvalMul64(y0, y1, h0, h1 uint64) (uint64, uint64) {
	h0r := bits.Reverse64(h0)
	h1r := bits.Reverse64(h1)
	h2 := h0 ^ h1
	h2r := h0r ^ h1r

	y0r := bits.Reverse64(y0)
	y1r := bits.Reverse64(y1)
	y2 := y0 ^ y1
	y2r := y0r ^ y1r

	z0 := bmul64(y0, h0)
	z1 := bmul64(y1, h1)
	z2 := bmul64(y2, h2)
	z0h := bmul64(y0r, h0r)
	z1h := bmul64(y1r, h1r)
	z2h := bmul64(y2r, h2r)
	z2 ^= z0 ^ z1
	z2h ^= z0h ^ z1h
	z0h = bits.Reverse64(z0h) >> 1
	z1h = bits.Reverse64(z1h) >> 1
	z2h = bits.Reverse64(z2h) >> 1

	v0 := z0
	v1 := z0h ^ z2
	v2 := z1 ^ z2h
	v3 := z1h

	v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
	v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
	v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
	v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)
	return v2, v3
}
