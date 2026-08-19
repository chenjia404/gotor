package relay

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// bandwidthLimiter 将 RelayBandwidthRate/Burst 接到出口数据面。
type bandwidthLimiter struct {
	lim *rate.Limiter
}

func newBandwidthLimiter(bytesPerSec, burst int64) *bandwidthLimiter {
	if bytesPerSec <= 0 {
		return nil
	}
	if burst < bytesPerSec {
		burst = bytesPerSec
	}
	if burst > 1<<30 {
		burst = 1 << 30
	}
	return &bandwidthLimiter{
		lim: rate.NewLimiter(rate.Limit(bytesPerSec), int(burst)),
	}
}

func (b *bandwidthLimiter) wait(ctx context.Context, n int) error {
	if b == nil || b.lim == nil || n <= 0 {
		return nil
	}
	// rate.Limiter.WaitN 上限为 burst；大块分片等待。
	for n > 0 {
		chunk := n
		if burst := b.lim.Burst(); chunk > burst {
			chunk = burst
		}
		if err := b.lim.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// exitConnGate 限制并发出口 TCP 连接，防止资源耗尽。
type exitConnGate struct {
	mu  sync.Mutex
	cur int
	max int
}

func newExitConnGate(max int) *exitConnGate {
	if max <= 0 {
		max = 1024
	}
	return &exitConnGate{max: max}
}

func (g *exitConnGate) acquire() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur >= g.max {
		return false
	}
	g.cur++
	return true
}

func (g *exitConnGate) release() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.cur > 0 {
		g.cur--
	}
	g.mu.Unlock()
}
