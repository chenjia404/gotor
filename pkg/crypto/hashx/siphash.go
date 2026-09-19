// Package hashx 实现 HashX 哈希函数族的解释器（tevador 设计）。
//
// 对照公开算法与测试向量：SipHash 论文附录、C Tor / Arti 的 HashX 向量。
// 纯 Go，无 CGO，不链接 LGPL 的 C 实现。
package hashx

import (
	"encoding/binary"
)

const hashxPerson = "HashX v1"

// sipState 是 HashX 使用的 SipHash 内部状态（无 vanilla 初始化常数）。
type sipState struct {
	v0, v1, v2, v3 uint64
}

func sipStateFromBytes(b []byte) sipState {
	return sipState{
		v0: binary.LittleEndian.Uint64(b[0:8]),
		v1: binary.LittleEndian.Uint64(b[8:16]),
		v2: binary.LittleEndian.Uint64(b[16:24]),
		v3: binary.LittleEndian.Uint64(b[24:32]),
	}
}

func (s *sipState) sipRound() {
	s.v0 += s.v1
	s.v2 += s.v3
	s.v1 = rotl64(s.v1, 13)
	s.v3 = rotl64(s.v3, 16)
	s.v1 ^= s.v0
	s.v3 ^= s.v2
	s.v0 = rotl64(s.v0, 32)

	s.v2 += s.v1
	s.v0 += s.v3
	s.v1 = rotl64(s.v1, 17)
	s.v3 = rotl64(s.v3, 21)
	s.v1 ^= s.v2
	s.v3 ^= s.v0
	s.v2 = rotl64(s.v2, 32)
}

func rotl64(x uint64, n uint) uint64 {
	return (x << n) | (x >> (64 - n))
}

// pairFromSeed 用 Blake2b-512 把任意长度种子拆成两份 SipHash 状态。
// HashX 把 "HashX v1" 作为 Blake2b 盐（不是个性化字段）。
func pairFromSeed(seed []byte) (sipState, sipState) {
	digest := blake2bHashX(seed)
	return sipStateFromBytes(digest[0:32]), sipStateFromBytes(digest[32:64])
}

// siphash13Ctr：HashX 的 SipHash-1-3 计数器模式，64 位输出。
func siphash13Ctr(key sipState, input uint64) uint64 {
	s := key
	s.v3 ^= input
	s.sipRound()
	s.v0 ^= input
	s.v2 ^= 0xff
	s.sipRound()
	s.sipRound()
	s.sipRound()
	return s.v0 ^ s.v1 ^ s.v2 ^ s.v3
}

// siphash24Ctr：HashX 的 SipHash-2-4 计数器模式，512 位（8×u64）输出。
func siphash24Ctr(key sipState, input uint64) [8]uint64 {
	s := key
	s.v1 ^= 0xee
	s.v3 ^= input
	s.sipRound()
	s.sipRound()
	s.v0 ^= input
	s.v2 ^= 0xee
	s.sipRound()
	s.sipRound()
	s.sipRound()
	s.sipRound()

	t := s
	t.v1 ^= 0xdd
	t.sipRound()
	t.sipRound()
	t.sipRound()
	t.sipRound()
	return [8]uint64{s.v0, s.v1, s.v2, s.v3, t.v0, t.v1, t.v2, t.v3}
}
