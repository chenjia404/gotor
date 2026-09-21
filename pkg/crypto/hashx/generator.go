package hashx

type opcodeSelector uint8

const (
	selNormal opcodeSelector = iota
	selImmediateSrc
	selMul
	selWideMul
	selTarget
	selBranch
)

var (
	wideMulOps     = [...]opcode{opSMulH, opUMulH}
	immediateOps   = [...]opcode{opRotate, opXorConst, opAddConst, opAddConst}
	normalOps      = [...]opcode{opRotate, opXorConst, opAddConst, opAddConst, opSub, opXor, opXorConst, opAddShift}
	branchMaskBits = 4
)

func chooseOpcodeSelector(p pass, subCycle uint16) opcodeSelector {
	n := int(subCycle) % 36
	switch {
	case n == 1:
		return selTarget
	case n == 19:
		return selBranch
	case n == 12 || n == 24:
		return selWideMul
	case n%3 == 0:
		return selMul
	case p == passRetry:
		return selImmediateSrc
	default:
		return selNormal
	}
}

type generator struct {
	rng        rngBuffer
	sched      scheduler
	val        validator
	lastSelOp  *opcode
	haveLastOp bool
	lastOp     opcode
}

func newGenerator(next func() uint64) *generator {
	return &generator{rng: newRngBuffer(next)}
}

func (g *generator) selectRegister(set regSet) (uint8, bool) {
	switch set.len() {
	case 0:
		return 0, false
	case 1:
		return set.index(0), true
	default:
		idx := g.rng.nextU32() % uint32(set.len()) // #nosec G115 -- 寄存器集合至多 8 个
		return set.index(int(idx)), true
	}
}

func (g *generator) selectOp(options []opcode) opcode {
	return options[int(g.rng.nextU8())%len(options)]
}

func (g *generator) selectConstantWeightBitMask(numOnes int) uint32 {
	var result uint32
	count := 0
	for count < numOnes {
		bit := uint32(1) << (uint(g.rng.nextU8()) % 32)
		if result&bit == 0 {
			result |= bit
			count++
		}
	}
	return result
}

func (g *generator) selectNonzeroU32(mask uint32) uint32 {
	for {
		r := g.rng.nextU32() & mask
		if r != 0 {
			return r
		}
	}
}

func (g *generator) generateProgram() ([]instruction, error) {
	out := make([]instruction, 0, numInstructions)
	for len(out) < numInstructions {
		inst, regw, ok := g.generateInstruction()
		if !ok {
			break
		}
		out = append(out, inst)
		g.val.commitInstruction(inst, regw)
		if !g.sched.advanceInstructionStream(inst.op) {
			break
		}
	}
	if !g.val.checkWholeProgram(&g.sched, len(out)) {
		return nil, ErrProgramConstraints
	}
	return out, nil
}

func (g *generator) generateInstruction() (instruction, registerWriter, bool) {
	for {
		if inst, w, ok := g.instructionGenAttempt(passOriginal); ok {
			return inst, w, true
		}
		if inst, w, ok := g.instructionGenAttempt(passRetry); ok {
			return inst, w, true
		}
		if !g.sched.stall() {
			return instruction{}, registerWriter{}, false
		}
	}
}

func (g *generator) applySelector(sel opcodeSelector) opcode {
	switch sel {
	case selTarget:
		return opTarget
	case selBranch:
		return opBranch
	case selMul:
		return opMul
	case selNormal:
		return g.selectOp(normalOps[:])
	case selImmediateSrc:
		return g.selectOp(immediateOps[:])
	case selWideMul:
		return g.selectOp(wideMulOps[:])
	default:
		return opMul
	}
}

func (g *generator) chooseOpcode(p pass) opcode {
	for {
		sub := g.sched.instructionStreamSubCycle()
		op := g.applySelector(chooseOpcodeSelector(p, sub))
		var prev *opcode
		if g.haveLastOp {
			prev = &g.lastOp
		}
		if opcodePairAllowed(prev, op) {
			g.lastOp = op
			g.haveLastOp = true
			return op
		}
	}
}

func (g *generator) instructionGenAttempt(p pass) (instruction, registerWriter, bool) {
	op := g.chooseOpcode(p)
	plan, ok := g.sched.instructionPlan(op)
	if !ok {
		return instruction{}, registerWriter{}, false
	}
	inst, w, ok := g.chooseInstruction(op, p, plan)
	if !ok {
		return instruction{}, registerWriter{}, false
	}
	g.sched.commitInstructionPlan(plan, inst)
	return inst, w, true
}

func (g *generator) chooseSrc(op opcode, plan instructionPlan) (uint8, bool) {
	issued := plan.cycleIssued()
	srcSet := regSetFilter(func(src uint8) bool {
		return g.sched.registerAvailable(src, issued)
	})
	srcSet = srcRegistersAllowed(srcSet, op)
	return g.selectRegister(srcSet)
}

func (g *generator) chooseDst(op opcode, p pass, writer registerWriter, src *uint8, plan instructionPlan) (uint8, bool) {
	chk := g.val.dstChecker(op, p, writer, src)
	issued := plan.cycleIssued()
	dstSet := regSetFilter(func(dst uint8) bool {
		return g.sched.registerAvailable(dst, issued) && chk.check(dst)
	})
	return g.selectRegister(dstSet)
}

func (g *generator) chooseSrcDst(op opcode, p pass, writerFn func(uint8) registerWriter, plan instructionPlan) (src, dst uint8, w registerWriter, ok bool) {
	src, ok = g.chooseSrc(op, plan)
	if !ok {
		return
	}
	w = writerFn(src)
	dst, ok = g.chooseDst(op, p, w, &src, plan)
	return
}

func (g *generator) chooseSrcDstFixedWriter(op opcode, p pass, w registerWriter, plan instructionPlan) (src, dst uint8, ok bool) {
	src, ok = g.chooseSrc(op, plan)
	if !ok {
		return
	}
	dst, ok = g.chooseDst(op, p, w, &src, plan)
	return
}

func (g *generator) chooseInstruction(op opcode, p pass, plan instructionPlan) (instruction, registerWriter, bool) {
	switch op {
	case opTarget:
		return instruction{op: opTarget}, registerWriter{kind: rwNone}, true
	case opBranch:
		return instruction{op: opBranch, imm: g.selectConstantWeightBitMask(branchMaskBits)}, registerWriter{kind: rwNone}, true
	case opUMulH:
		w := registerWriter{kind: rwUMulH, arg: g.rng.nextU32()}
		src, dst, ok := g.chooseSrcDstFixedWriter(op, p, w, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opUMulH, src: src, dst: dst}, w, true
	case opSMulH:
		w := registerWriter{kind: rwSMulH, arg: g.rng.nextU32()}
		src, dst, ok := g.chooseSrcDstFixedWriter(op, p, w, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opSMulH, src: src, dst: dst}, w, true
	case opMul:
		src, dst, w, ok := g.chooseSrcDst(op, p, func(src uint8) registerWriter {
			return registerWriter{kind: rwMul, arg: uint32(src)}
		}, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opMul, src: src, dst: dst}, w, true
	case opSub:
		src, dst, w, ok := g.chooseSrcDst(op, p, func(src uint8) registerWriter {
			return registerWriter{kind: rwAddSub, arg: uint32(src)}
		}, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opSub, src: src, dst: dst}, w, true
	case opXor:
		src, dst, w, ok := g.chooseSrcDst(op, p, func(src uint8) registerWriter {
			return registerWriter{kind: rwXor, arg: uint32(src)}
		}, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opXor, src: src, dst: dst}, w, true
	case opAddShift:
		left := uint8(g.rng.nextU32() & 3)
		src, dst, w, ok := g.chooseSrcDst(op, p, func(src uint8) registerWriter {
			return registerWriter{kind: rwAddSub, arg: uint32(src)}
		}, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opAddShift, src: src, dst: dst, shift: left}, w, true
	case opAddConst:
		w := registerWriter{kind: rwAddConst}
		srcImm := g.selectNonzeroU32(^uint32(0))
		dst, ok := g.chooseDst(op, p, w, nil, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opAddConst, dst: dst, imm: srcImm}, w, true
	case opXorConst:
		w := registerWriter{kind: rwXorConst}
		srcImm := g.selectNonzeroU32(^uint32(0))
		dst, ok := g.chooseDst(op, p, w, nil, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opXorConst, dst: dst, imm: srcImm}, w, true
	case opRotate:
		w := registerWriter{kind: rwRotate}
		rot := uint8(g.selectNonzeroU32(63)) // #nosec G115 -- 旋转量已限制 1..63
		dst, ok := g.chooseDst(op, p, w, nil, plan)
		if !ok {
			return instruction{}, registerWriter{}, false
		}
		return instruction{op: opRotate, dst: dst, shift: rot}, w, true
	default:
		return instruction{}, registerWriter{}, false
	}
}
