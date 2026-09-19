package hashx

// rngBuffer 把 64 位 PRNG 拆成 u32 / u8 队列，匹配 HashX 生成器的消费顺序。
// u64 惰性抽取；u32 先高 32 位；u8 按小端字节从尾部弹出。
type rngBuffer struct {
	next   func() uint64
	u8buf  [7]byte
	u8n    int
	u32    uint32
	hasU32 bool
}

func newRngBuffer(next func() uint64) rngBuffer {
	return rngBuffer{next: next}
}

func (r *rngBuffer) nextU32() uint32 {
	if r.hasU32 {
		r.hasU32 = false
		return r.u32
	}
	v := r.next()
	r.u32 = uint32(v)
	r.hasU32 = true
	return uint32(v >> 32)
}

func (r *rngBuffer) nextU8() uint8 {
	if r.u8n > 0 {
		r.u8n--
		return r.u8buf[r.u8n]
	}
	v := r.next()
	for i := 0; i < 7; i++ {
		r.u8buf[i] = byte(v >> (8 * i))
	}
	r.u8n = 7
	return byte(v >> 56)
}

// sipRand 是基于 SipHash-1-3 计数器的 64 位 PRNG。
type sipRand struct {
	key     sipState
	counter uint64
}

func newSipRand(key sipState) sipRand {
	return sipRand{key: key}
}

func (s *sipRand) nextU64() uint64 {
	v := siphash13Ctr(s.key, s.counter)
	s.counter++
	return v
}
