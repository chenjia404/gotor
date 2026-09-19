package hashx

const (
	requiredInstructions = numInstructions
	requiredOverallCycle = 194
	requiredMultiplies   = 192
)

type pass uint8

const (
	passOriginal pass = iota
	passRetry
)

type registerWriterKind uint8

const (
	rwNone registerWriterKind = iota
	rwMul
	rwUMulH
	rwSMulH
	rwAddSub
	rwAddConst
	rwXor
	rwXorConst
	rwRotate
)

type registerWriter struct {
	kind registerWriterKind
	arg  uint32 // 寄存器 id 或宽乘用的额外 u32
}

func isMultiply(op opcode) bool {
	return op == opMul || op == opSMulH || op == opUMulH
}

func disallowSrcIsDst(op opcode) bool {
	return op == opAddShift || op == opMul || op == opSub || op == opXor
}

func disallowOpcodePair(previous, proposed opcode) bool {
	switch proposed {
	case opMul, opUMulH, opSMulH, opTarget, opBranch:
		return false
	case opAddConst, opXor, opXorConst, opRotate:
		return previous == proposed
	case opAddShift, opSub:
		return previous == opAddShift || previous == opSub
	default:
		return false
	}
}

func writerPairAllowed(p pass, last, this registerWriter) bool {
	if last.kind == rwMul && this.kind == rwMul && p == passOriginal {
		return false
	}
	return last != this
}

type validator struct {
	writers  [numRegisters]registerWriter
	mulCount int
}

func (v *validator) commitInstruction(inst instruction, regw registerWriter) {
	if isMultiply(inst.op) {
		v.mulCount++
	}
	if dst, ok := inst.destination(); ok {
		v.writers[dst] = regw
	}
}

func (v *validator) checkWholeProgram(sched *scheduler, nInst int) bool {
	return nInst == requiredInstructions &&
		sched.overallLatency() == requiredOverallCycle &&
		v.mulCount == requiredMultiplies
}

type dstChecker struct {
	pass         pass
	writerInfo   registerWriter
	writers      *[numRegisters]registerWriter
	opIsAddShift bool
	disallowEq   int // -1 或 src 寄存器
}

func (v *validator) dstChecker(op opcode, p pass, writer registerWriter, src *uint8) dstChecker {
	d := dstChecker{
		pass:         p,
		writerInfo:   writer,
		writers:      &v.writers,
		opIsAddShift: op == opAddShift,
		disallowEq:   -1,
	}
	if src != nil && disallowSrcIsDst(op) {
		d.disallowEq = int(*src)
	}
	return d
}

func (d dstChecker) check(dst uint8) bool {
	if d.opIsAddShift && dst == regR5 {
		return false
	}
	if d.disallowEq >= 0 && int(dst) == d.disallowEq {
		return false
	}
	return writerPairAllowed(d.pass, d.writers[dst], d.writerInfo)
}

func srcRegistersAllowed(available regSet, op opcode) regSet {
	if op == opAddShift && available.contains(regR5) && available.len() == 2 {
		return regSetFilter(func(r uint8) bool { return r == regR5 })
	}
	return available
}

func opcodePairAllowed(previous *opcode, proposed opcode) bool {
	if previous == nil {
		return true
	}
	return !disallowOpcodePair(*previous, proposed)
}
