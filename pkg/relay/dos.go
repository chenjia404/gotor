package relay

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/config"
)

// DoS 拒绝原因（CREATE2 走 DESTROY RESOURCELIMIT；连接在 accept 处关闭）。
var (
	errDoSConnection = fmt.Errorf("DoS: concurrent OR connections from this address")
	errDoSCircuit    = fmt.Errorf("DoS: circuit creation rate exceeded")
)

// DoSConfig 是接线用的已解析开关。Enabled=auto 且无共识时调用方应把 Enabled 置 false。
type DoSConfig struct {
	CircuitEnabled  bool
	ConnEnabled     bool
	RefuseSingleHop bool
	MinConnections  int
	Rate            int
	Burst           int
	Defense         time.Duration
	MaxConcurrent   int
}

// DoSGuard 对齐 C Tor dos.c 的最小切片：每 IP 并发 OR + CREATE2 令牌桶 + 单跳拒绝开关。
// 不是 ProtectionManager（那套未接到 CREATE2，也不解析官方 DoS* 键）。
type DoSGuard struct {
	circOn    bool
	connOn    bool
	refuseHop bool
	minConns  int
	rate      float64
	burst     float64
	defense   time.Duration
	maxConns  int
	mu        sync.Mutex
	ips       map[string]*dosIP
	lastPurge time.Time
	nowFn     func() time.Time
}

type dosIP struct {
	conns       int
	tokens      float64
	lastRefill  time.Time
	markedUntil time.Time
}

// NewDoSGuardFromConfig 仅当官方键显式为 1（或 RefuseSingleHop）时启用。
// auto/0 视为关：本切片不读共识 DoS* 参数。
func NewDoSGuardFromConfig(cfg *config.Config) *DoSGuard {
	if cfg == nil {
		return nil
	}
	g := NewDoSGuard(DoSConfig{
		CircuitEnabled:  cfg.DoSCircuitCreationEnabled == config.DoSEnabledOn,
		ConnEnabled:     cfg.DoSConnectionEnabled == config.DoSEnabledOn,
		RefuseSingleHop: cfg.DoSRefuseSingleHopClient,
		MinConnections:  cfg.DoSCircuitCreationMinConnections,
		Rate:            cfg.DoSCircuitCreationRate,
		Burst:           cfg.DoSCircuitCreationBurst,
		Defense:         cfg.DoSCircuitCreationDefenseTime,
		MaxConcurrent:   cfg.DoSConnectionMaxConcurrentCount,
	})
	if g == nil || (!g.circOn && !g.connOn && !g.refuseHop) {
		return nil
	}
	return g
}

// NewDoSGuard 构造守卫；全关则返回仍可调用的空操作对象（测试用）。
func NewDoSGuard(cfg DoSConfig) *DoSGuard {
	minC := cfg.MinConnections
	if minC < 1 {
		minC = 3
	}
	rate := cfg.Rate
	if rate < 1 {
		rate = 3
	}
	burst := cfg.Burst
	if burst < 1 {
		burst = 90
	}
	maxC := cfg.MaxConcurrent
	if maxC < 1 {
		maxC = 100
	}
	def := cfg.Defense
	if def <= 0 {
		def = time.Hour
	}
	return &DoSGuard{
		circOn:    cfg.CircuitEnabled,
		connOn:    cfg.ConnEnabled,
		refuseHop: cfg.RefuseSingleHop,
		minConns:  minC,
		rate:      float64(rate),
		burst:     float64(burst),
		defense:   def,
		maxConns:  maxC,
		ips:       make(map[string]*dosIP),
		lastPurge: time.Now(),
		nowFn:     time.Now,
	}
}

func (g *DoSGuard) now() time.Time {
	if g != nil && g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

// RefuseSingleHop 对应 DoSRefuseSingleHopClient。
func (g *DoSGuard) RefuseSingleHop() bool {
	return g != nil && g.refuseHop
}

// OnConnect 在 accept 之后、TLS 之前计数。ConnEnabled 时超过每 IP 上限则拒绝。
// 即使连接防御关闭，仍计数，供电路创建 MinConnections 使用。
func (g *DoSGuard) OnConnect(ip string) error {
	if g == nil || ip == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maybePurgeLocked(g.now())
	st := g.getLocked(ip)
	if g.connOn && st.conns >= g.maxConns {
		return errDoSConnection
	}
	st.conns++
	return nil
}

// OnDisconnect 释放每 IP 连接计数。
func (g *DoSGuard) OnDisconnect(ip string) {
	if g == nil || ip == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.ips[ip]
	if !ok {
		return
	}
	st.conns--
	if st.conns < 0 {
		st.conns = 0
	}
	if st.conns == 0 && g.now().After(st.markedUntil) {
		delete(g.ips, ip)
	}
}

// AllowCreate2 在并发连接数达到 MinConnections 后对该 IP 套令牌桶。
// 桶空则进入 DefenseTimePeriod，期间一律拒绝。
func (g *DoSGuard) AllowCreate2(ip string) error {
	if g == nil || !g.circOn || ip == "" {
		return nil
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.getLocked(ip)
	if now.Before(st.markedUntil) {
		return errDoSCircuit
	}
	if st.conns < g.minConns {
		return nil
	}
	g.refillLocked(st, now)
	if st.tokens >= 1 {
		st.tokens--
		return nil
	}
	st.markedUntil = now.Add(g.defense)
	return errDoSCircuit
}

func (g *DoSGuard) getLocked(ip string) *dosIP {
	st, ok := g.ips[ip]
	if !ok {
		st = &dosIP{tokens: g.burst, lastRefill: g.now()}
		g.ips[ip] = st
	}
	return st
}

func (g *DoSGuard) refillLocked(st *dosIP, now time.Time) {
	elapsed := now.Sub(st.lastRefill).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * g.rate
		if st.tokens > g.burst {
			st.tokens = g.burst
		}
		st.lastRefill = now
	}
}

func (g *DoSGuard) maybePurgeLocked(now time.Time) {
	if now.Sub(g.lastPurge) < 10*time.Minute {
		return
	}
	g.lastPurge = now
	for ip, st := range g.ips {
		if st.conns == 0 && now.After(st.markedUntil) && now.Sub(st.lastRefill) > g.defense {
			delete(g.ips, ip)
		}
	}
}

func clientIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return clientIPString(addr.String())
}

func clientIPString(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
