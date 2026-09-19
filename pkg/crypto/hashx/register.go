package hashx

const (
	numRegisters = 8
	regR5        = 5
)

type registerFile [numRegisters]uint64

func newRegisterFile(key sipState, input uint64) registerFile {
	return siphash24Ctr(key, input)
}

func (r registerFile) digest(key sipState) [4]uint64 {
	x := sipState{
		v0: r[0] + key.v0,
		v1: r[1] + key.v1,
		v2: r[2],
		v3: r[3],
	}
	y := sipState{
		v0: r[4],
		v1: r[5],
		v2: r[6] + key.v2,
		v3: r[7] + key.v3,
	}
	x.sipRound()
	y.sipRound()
	return [4]uint64{x.v0 ^ y.v0, x.v1 ^ y.v1, x.v2 ^ y.v2, x.v3 ^ y.v3}
}

type regSet struct {
	ids [numRegisters]uint8
	n   int
}

func (s *regSet) len() int { return s.n }

func (s *regSet) contains(id uint8) bool {
	for i := 0; i < s.n; i++ {
		if s.ids[i] == id {
			return true
		}
	}
	return false
}

func (s *regSet) index(i int) uint8 { return s.ids[i] }

func regSetFilter(pred func(uint8) bool) regSet {
	var s regSet
	for r := uint8(0); r < numRegisters; r++ {
		if pred(r) {
			s.ids[s.n] = r
			s.n++
		}
	}
	return s
}
