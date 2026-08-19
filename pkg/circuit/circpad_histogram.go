// Package circuit — Circpad 直方图延迟采样（padding-spec / proposal 302）。
//
// 对照 C Tor circpad_machine_sample_delay：按 token 权重选 bin，再在
// [edge[i], edge[i+1]) 微秒区间均匀采样。
package circuit

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// CircpadDelayInfinite 表示不调度 padding（无穷 bin / 无 token）。
const CircpadDelayInfinite = time.Duration(-1)

// CircpadHistogram 不可变直方图（与 C Tor 无 token removal 的 setup 机一致）。
// Edges 长度 = Bins+1；最后一档为 infinity（不发送）。
// 对 setup 机常见 Edges=[lo, hi] 且只有 Bins[0] 有 token，infinity 隐式。
type CircpadHistogram struct {
	// Edges 微秒边界，严格递增；Bins[i] 对应 [Edges[i], Edges[i+1])。
	Edges []uint32
	// Bins token 计数；len = len(Edges)-1（不含 infinity）或含 infinity。
	Bins []uint32
}

// SampleDelay 采样下一次 padding 前的等待时间。
func (h *CircpadHistogram) SampleDelay() (time.Duration, error) {
	if h == nil || len(h.Edges) < 2 || len(h.Bins) == 0 {
		return CircpadDelayInfinite, fmt.Errorf("empty histogram")
	}
	nBins := len(h.Edges) - 1
	if len(h.Bins) < nBins {
		nBins = len(h.Bins)
	}
	var total uint64
	for i := 0; i < nBins; i++ {
		total += uint64(h.Bins[i])
	}
	if total == 0 {
		return CircpadDelayInfinite, nil
	}
	choice, err := randUint64(total)
	if err != nil {
		return 0, err
	}
	var weight uint64
	bin := 0
	for bin < nBins {
		weight += uint64(h.Bins[bin])
		if weight > choice {
			break
		}
		bin++
	}
	if bin >= nBins {
		return CircpadDelayInfinite, nil
	}
	// infinity bin：Edges 比 Bins 多一档且选中最后一档
	if bin == len(h.Edges)-2 && len(h.Bins) >= len(h.Edges)-1 {
		// 若 Bins 最后一档是 infinity（C Tor histogram_len 含 infinity）
		// setup 机：histogram_len=2，edges[0],edges[1]，bins[0] only — 无 infinity token
	}
	lo := uint64(h.Edges[bin])
	hi := uint64(h.Edges[bin+1])
	if hi <= lo {
		return time.Duration(lo) * time.Microsecond, nil
	}
	span := hi - lo
	off, err := randUint64(span)
	if err != nil {
		return 0, err
	}
	usec := lo + off
	return time.Duration(usec) * time.Microsecond, nil
}

func randUint64(max uint64) (uint64, error) {
	if max == 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(max))
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}

// RelayIntroObfuscateHistogram 对照中继 intro 机：1–10ms 批处理感。
func RelayIntroObfuscateHistogram() CircpadHistogram {
	return CircpadHistogram{
		Edges: []uint32{1000, 10000},
		Bins:  []uint32{1000},
	}
}

// ClientRendObfuscateHistogram 对照客户端 rend 机：0–1ms，尽快发出 DROP。
func ClientRendObfuscateHistogram() CircpadHistogram {
	return CircpadHistogram{
		Edges: []uint32{0, 1000},
		Bins:  []uint32{1000},
	}
}

// MustSampleDelay 测试/调试用；失败返回 0。
func MustSampleDelay(h CircpadHistogram) time.Duration {
	d, err := h.SampleDelay()
	if err != nil || d < 0 {
		return 0
	}
	return d
}
