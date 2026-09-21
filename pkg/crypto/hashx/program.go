package hashx

import "math/bits"

const numInstructions = 512

type opcode uint8

const (
	opMul opcode = iota
	opUMulH
	opSMulH
	opAddShift
	opAddConst
	opSub
	opXor
	opXorConst
	opRotate
	opTarget
	opBranch
)

type instruction struct {
	op    opcode
	dst   uint8
	src   uint8
	shift uint8
	imm   uint32
}

func (inst instruction) destination() (uint8, bool) {
	switch inst.op {
	case opTarget, opBranch:
		return 0, false
	default:
		return inst.dst, true
	}
}

func interpret(prog []instruction, regs *registerFile) {
	pc := 0
	allowBranch := true
	branchTarget := -1
	var mulhResult uint32

	for pc < len(prog) {
		inst := prog[pc]
		next := pc + 1
		switch inst.op {
		case opTarget:
			branchTarget = pc
			pc = next
		case opBranch:
			if allowBranch && (inst.imm&mulhResult) == 0 && branchTarget >= 0 {
				allowBranch = false
				pc = branchTarget
			} else {
				pc = next
			}
		case opAddShift:
			a := regs[inst.dst]
			b := regs[inst.src]
			regs[inst.dst] = a + (b << inst.shift)
			pc = next
		case opRotate:
			regs[inst.dst] = bits.RotateLeft64(regs[inst.dst], -int(inst.shift))
			pc = next
		case opMul:
			regs[inst.dst] *= regs[inst.src]
			pc = next
		case opSub:
			regs[inst.dst] -= regs[inst.src]
			pc = next
		case opXor:
			regs[inst.dst] ^= regs[inst.src]
			pc = next
		case opUMulH:
			hi, _ := bits.Mul64(regs[inst.dst], regs[inst.src])
			mulhResult = uint32(hi) // #nosec G115 -- HashX 32 位寄存器截断
			regs[inst.dst] = hi
			pc = next
		case opSMulH:
			hi := mulhSigned(regs[inst.dst], regs[inst.src])
			mulhResult = uint32(hi) // #nosec G115 -- HashX 32 位寄存器截断
			regs[inst.dst] = hi
			pc = next
		case opXorConst:
			regs[inst.dst] ^= uint64(int64(int32(inst.imm))) // #nosec G115 -- HashX 有符号立即数符号扩展
			pc = next
		case opAddConst:
			regs[inst.dst] += uint64(int64(int32(inst.imm))) // #nosec G115 -- HashX 有符号立即数符号扩展
			pc = next
		default:
			pc = next
		}
	}
}

func mulhSigned(a, b uint64) uint64 {
	hi, _ := bits.Mul64(a, b)
	if int64(a) < 0 { // #nosec G115 -- HashX 有符号 mulh 把 u64 当 i64
		hi -= b
	}
	if int64(b) < 0 { // #nosec G115 -- HashX 有符号 mulh 把 u64 当 i64
		hi -= a
	}
	return hi
}
