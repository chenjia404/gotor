// Package equix 实现 Equi-X（Equihash(60,3) + HashX）。
//
// 对照 C Tor test_crypto_equix 与 Arti equix 公开测试向量。纯 Go，无 CGO。
package equix

import (
	"encoding/binary"
	"errors"

	"github.com/opd-ai/go-tor/pkg/crypto/hashx"
)

const (
	equihashN   = 60
	equihashK   = 3
	numItems    = 1 << equihashK // 8
	solutionLen = numItems * 2   // 16 字节
	numBuckets  = 256
)

// ErrProgramConstraints 该挑战无法构造 HashX 程序。
var ErrProgramConstraints = hashx.ErrProgramConstraints

// ErrOrder 解的树序不满足 Equi-X 约束。
var ErrOrder = errors.New("equix: 解的顺序不合法")

// ErrHashSum 哈希树部分和校验失败。
var ErrHashSum = errors.New("equix: 哈希部分和校验失败")

// Solution 是 8 个 16 位索引（小端打包为 16 字节）。
type Solution [numItems]uint16

// Bytes 返回 16 字节小端表示。
func (s Solution) Bytes() [solutionLen]byte {
	var out [solutionLen]byte
	for i, item := range s {
		binary.LittleEndian.PutUint16(out[i*2:], item)
	}
	return out
}

// SolutionFromBytes 解析 16 字节解并检查树序。
func SolutionFromBytes(b []byte) (Solution, error) {
	if len(b) != solutionLen {
		return Solution{}, errors.New("equix: 解长度必须为 16")
	}
	var s Solution
	for i := 0; i < numItems; i++ {
		s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	if !checkTreeOrder(s[:]) {
		return Solution{}, ErrOrder
	}
	return s, nil
}

// EquiX 绑定某挑战字符串的 HashX 实例。
type EquiX struct {
	hash *hashx.HashX
}

// New 构造 Equi-X 实例。约千分之几的挑战会返回 ErrProgramConstraints。
func New(challenge []byte) (*EquiX, error) {
	h, err := hashx.New(challenge)
	if err != nil {
		return nil, err
	}
	return &EquiX{hash: h}, nil
}

func (e *EquiX) itemHash(item uint16) uint64 {
	return e.hash.HashToU64(uint64(item))
}

// Verify 校验解的树序与各层部分和。
func (e *EquiX) Verify(sol Solution) error {
	if !checkTreeOrder(sol[:]) {
		return ErrOrder
	}
	if _, ok := checkTreeSums(e, sol[:], equihashN); !ok {
		return ErrHashSum
	}
	return nil
}

func checkTreeOrder(items []uint16) bool {
	mid := len(items) / 2
	left, right := items[:mid], items[mid:]
	if !branchesSorted(left, right) {
		return false
	}
	if len(items) == 2 {
		return true
	}
	return checkTreeOrder(left) && checkTreeOrder(right)
}

func branchesSorted(left, right []uint16) bool {
	for i := 0; i < len(left); i++ {
		l := left[len(left)-1-i]
		r := right[len(right)-1-i]
		if l < r {
			return true
		}
		if l > r {
			return false
		}
	}
	return true
}

func sortTreeOrder(items []uint16) {
	if len(items) <= 1 {
		return
	}
	mid := len(items) / 2
	if len(items) > 2 {
		sortTreeOrder(items[:mid])
		sortTreeOrder(items[mid:])
	}
	if !branchesSorted(items[:mid], items[mid:]) {
		tmp := make([]uint16, mid)
		copy(tmp, items[:mid])
		copy(items[:mid], items[mid:])
		copy(items[mid:], tmp)
	}
}

func checkTreeSums(e *EquiX, items []uint16, nBits int) (uint64, bool) {
	var sum uint64
	if len(items) == 2 {
		sum = e.itemHash(items[0]) + e.itemHash(items[1])
	} else {
		mid := len(items) / 2
		left, ok := checkTreeSums(e, items[:mid], nBits/2)
		if !ok {
			return 0, false
		}
		right, ok := checkTreeSums(e, items[mid:], nBits/2)
		if !ok {
			return 0, false
		}
		sum = left + right
	}
	mask := (uint64(1) << nBits) - 1
	if sum&mask != 0 {
		return 0, false
	}
	return sum, true
}
