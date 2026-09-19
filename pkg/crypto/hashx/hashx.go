package hashx

import (
	"encoding/binary"
	"errors"
)

// ErrProgramConstraints 表示该种子无法生成满足约束的 HashX 程序，求解器应换种子。
var ErrProgramConstraints = errors.New("hashx: 程序约束不满足，跳过此种子")

// HashX 是针对某一种子预生成的哈希函数。
type HashX struct {
	registerKey sipState
	program     []instruction
}

const fullSize = 32

// New 由种子生成 HashX 实例（仅解释器）。
func New(seed []byte) (*HashX, error) {
	key0, key1 := pairFromSeed(seed)
	rng := newSipRand(key0)
	gen := newGenerator(rng.nextU64)
	prog, err := gen.generateProgram()
	if err != nil {
		return nil, err
	}
	return &HashX{registerKey: key1, program: prog}, nil
}

// HashToU64 返回 64 位输出（Equi-X 使用）。
func (h *HashX) HashToU64(input uint64) uint64 {
	return h.hashToRegs(input).digest(h.registerKey)[0]
}

// HashToBytes 返回 32 字节小端输出（对照 HashX 测试向量）。
func (h *HashX) HashToBytes(input uint64) [fullSize]byte {
	words := h.hashToRegs(input).digest(h.registerKey)
	var out [fullSize]byte
	for i, w := range words {
		binary.LittleEndian.PutUint64(out[i*8:(i+1)*8], w)
	}
	return out
}

func (h *HashX) hashToRegs(input uint64) registerFile {
	regs := newRegisterFile(h.registerKey, input)
	interpret(h.program, &regs)
	return regs
}
