package equix

type hashItem struct {
	hash uint64
	idx  uint16
}

type pair2 struct {
	hash uint64
	a, b uint16
}

type pair4 struct {
	hash  uint64
	items [4]uint16
}

// Solve 搜索该挑战的 Equi-X 解。
func (e *EquiX) Solve() []Solution {
	var buckets [numBuckets][]hashItem
	for i := 0; i <= 0xffff; i++ {
		h := e.itemHash(uint16(i))
		b := h & 0xff
		buckets[b] = append(buckets[b], hashItem{hash: h, idx: uint16(i)})
	}

	var layer1 [numBuckets][]pair2
	for first := 0; first <= numBuckets/2; first++ {
		second := (numBuckets - first) % numBuckets
		for i, x := range buckets[first] {
			ys := buckets[second]
			start := 0
			if first == second {
				start = i + 1
			}
			for _, y := range ys[start:] {
				sum := x.hash + y.hash
				if sum&((1<<15)-1) == 0 {
					res := sum >> 15
					layer1[res&0xff] = append(layer1[res&0xff], pair2{hash: res, a: x.idx, b: y.idx})
				}
			}
		}
	}

	var layer2 [numBuckets][]pair4
	for first := 0; first <= numBuckets/2; first++ {
		second := (numBuckets - first) % numBuckets
		for i, x := range layer1[first] {
			ys := layer1[second]
			start := 0
			if first == second {
				start = i + 1
			}
			for _, y := range ys[start:] {
				sum := x.hash + y.hash
				if sum&((1<<15)-1) == 0 {
					res := sum >> 15
					layer2[res&0xff] = append(layer2[res&0xff], pair4{
						hash:  res,
						items: [4]uint16{x.a, x.b, y.a, y.b},
					})
				}
			}
		}
	}

	var out []Solution
	seen := make(map[Solution]struct{})
	for first := 0; first <= numBuckets/2; first++ {
		second := (numBuckets - first) % numBuckets
		for i, x := range layer2[first] {
			ys := layer2[second]
			start := 0
			if first == second {
				start = i + 1
			}
			for _, y := range ys[start:] {
				sum := x.hash + y.hash
				if sum&((1<<30)-1) != 0 {
					continue
				}
				var items [8]uint16
				copy(items[0:4], x.items[:])
				copy(items[4:8], y.items[:])
				sortTreeOrder(items[:])
				sol := Solution(items)
				if _, ok := seen[sol]; ok {
					continue
				}
				seen[sol] = struct{}{}
				if e.Verify(sol) == nil {
					out = append(out, sol)
				}
			}
		}
	}
	return out
}
