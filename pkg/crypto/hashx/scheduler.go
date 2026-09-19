package hashx

const (
	targetCycles      = 192
	maxLatency        = 4
	scheduleSize      = targetCycles + maxLatency
	numExecPorts      = 3
	subCyclesPerCycle = 3
	subCycleMax       = scheduleSize*subCyclesPerCycle - 1
)

const (
	portP5   uint8 = 1 << 0
	portP0   uint8 = 1 << 1
	portP1   uint8 = 1 << 2
	portP01        = portP0 | portP1
	portP05        = portP0 | portP5
	portP015       = portP0 | portP1 | portP5
)

func instructionLatency(op opcode) int {
	switch op {
	case opMul:
		return 3
	case opSMulH, opUMulH:
		return 4
	default:
		return 1
	}
}

func microOperations(op opcode) (uint8, uint8, bool) {
	switch op {
	case opAddConst, opSub, opXor, opXorConst:
		return portP015, 0, false
	case opMul:
		return portP1, 0, false
	case opAddShift:
		return portP01, 0, false
	case opRotate:
		return portP05, 0, false
	case opSMulH, opUMulH:
		return portP1, portP5, true
	case opBranch, opTarget:
		return portP015, portP015, true
	default:
		return portP015, 0, false
	}
}

func instructionSubCycleCount(op opcode) int {
	if _, _, two := microOperations(op); two {
		return 2
	}
	return 1
}

type scheduler struct {
	subCycle uint16
	cycle    uint8
	ports    [numExecPorts][4]uint64 // 196 bit busy flags
	latency  [numRegisters]uint8
}

func (s *scheduler) stall() bool {
	return s.advance(subCyclesPerCycle)
}

func (s *scheduler) instructionStreamSubCycle() uint16 {
	return s.subCycle
}

func (s *scheduler) advance(n int) bool {
	res := int(s.subCycle) + n
	if res >= subCycleMax {
		return false
	}
	cyc := res / subCyclesPerCycle
	if cyc >= targetCycles {
		return false
	}
	s.subCycle = uint16(res)
	s.cycle = uint8(cyc)
	return true
}

func (s *scheduler) advanceInstructionStream(op opcode) bool {
	return s.advance(instructionSubCycleCount(op))
}

type instructionPlan struct {
	cycle      uint8
	firstPort  uint8
	secondPort uint8
	hasSecond  bool
}

func (p instructionPlan) cycleIssued() uint8 { return p.cycle }

func (p instructionPlan) cycleRetired(op opcode) uint8 {
	return p.cycle + uint8(instructionLatency(op))
}

func (s *scheduler) portBusy(port, cycle int) bool {
	word := cycle / 64
	bit := uint64(1) << (uint(cycle) % 64)
	return s.ports[port][word]&bit != 0
}

func (s *scheduler) setPortBusy(port, cycle int) {
	word := cycle / 64
	bit := uint64(1) << (uint(cycle) % 64)
	s.ports[port][word] |= bit
}

func (s *scheduler) microPlan(begin uint8, ports uint8) (cycle uint8, portIdx uint8, ok bool) {
	c := int(begin)
	for {
		for idx := uint8(0); idx < numExecPorts; idx++ {
			if ports&(1<<idx) != 0 && !s.portBusy(int(idx), c) {
				return uint8(c), idx, true
			}
		}
		c++
		if c >= scheduleSize {
			return 0, 0, false
		}
	}
}

func (s *scheduler) instructionPlan(op opcode) (instructionPlan, bool) {
	first, second, two := microOperations(op)
	if !two {
		c, p, ok := s.microPlan(s.cycle, first)
		if !ok {
			return instructionPlan{}, false
		}
		return instructionPlan{cycle: c, firstPort: p}, true
	}
	c := int(s.cycle)
	for {
		c1, p1, ok1 := s.microPlan(uint8(c), first)
		c2, p2, ok2 := s.microPlan(uint8(c), second)
		if ok1 && ok2 && c1 == c2 {
			return instructionPlan{cycle: c1, firstPort: p1, secondPort: p2, hasSecond: true}, true
		}
		c++
		if c >= scheduleSize {
			return instructionPlan{}, false
		}
	}
}

func (s *scheduler) commitInstructionPlan(plan instructionPlan, inst instruction) {
	s.setPortBusy(int(plan.firstPort), int(plan.cycle))
	if plan.hasSecond {
		s.setPortBusy(int(plan.secondPort), int(plan.cycle))
	}
	if dst, ok := inst.destination(); ok {
		s.latency[dst] = plan.cycleRetired(inst.op)
	}
}

func (s *scheduler) registerAvailable(reg, cycle uint8) bool {
	return s.latency[reg] <= cycle
}

func (s *scheduler) overallLatency() int {
	max := uint8(0)
	for _, l := range s.latency {
		if l > max {
			max = l
		}
	}
	return int(max)
}
