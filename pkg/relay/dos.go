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
	errDoSConnection  = fmt.Errorf("DoS: concurrent OR connections from this address")
	errDoSConnectRate = fmt.Errorf("DoS: connection rate exceeded")
	errDoSCircuit     = fmt.Errorf("DoS: circuit creation rate exceeded")
)

// 连接速率默认值对齐 C Tor dos.c：Rate 20、Burst 40、防御窗 24h。
const (
	dosConnConnectRateDefault    = 20
	dosConnConnectBurstDefault   = 40
	dosConnConnectDefenseDefault = 24 * time.Hour
	dosParamMax                  = 1<<31 - 1
	dosConnDefenseMinSec         = 10
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

// DoSGuard 对齐 C Tor dos.c 的最小切片：每 IP 并发 OR + 连接速率桶 + CREATE2 令牌桶 + 单跳拒绝开关。
// auto 跟共识 DoSCircuitCreationEnabled / DoSConnectionEnabled。不是完整 dos.c（无 StreamCreation）。
// 不是 ProtectionManager（那套未接到 CREATE2，也不解析官方 DoS* 键）。
type DoSGuard struct {
	circOn       bool
	connOn       bool
	refuseHop    bool
	circMode     int
	connMode     int
	minConns     int
	rate         float64
	burst        float64
	defense      time.Duration
	maxConns     int
	connRate     float64
	connBurst    float64
	connDef      time.Duration
	connRateCfg  int
	connBurstCfg int
	connDefCfg   time.Duration
	mu           sync.Mutex
	ips          map[string]*dosIP
	lastPurge    time.Time
	nowFn        func() time.Time
}

type dosIP struct {
	conns       int
	tokens      float64
	lastRefill  time.Time
	markedUntil time.Time
	connTokens  float64
	connLast    time.Time
	connMarked  time.Time
}

// NewDoSGuardFromConfig 构造守卫。Enabled=auto 时先关，等 ApplyConsensus 读共识 DoS*。
// 显式 0 保持关；显式 1 立即开。始终返回非空对象，以便后续跟共识。
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
	if g == nil {
		return nil
	}
	g.circMode = cfg.DoSCircuitCreationEnabled
	g.connMode = cfg.DoSConnectionEnabled
	g.connRateCfg = cfg.DoSConnectionConnectRate
	g.connBurstCfg = cfg.DoSConnectionConnectBurst
	g.connDefCfg = cfg.DoSConnectionConnectDefenseTime
	g.connRate = dosConnConnectRateDefault
	g.connBurst = dosConnConnectBurstDefault
	g.connDef = dosConnConnectDefenseDefault
	if g.connRateCfg > 0 {
		g.connRate = float64(g.connRateCfg)
	}
	if g.connBurstCfg > 0 {
		g.connBurst = float64(g.connBurstCfg)
	}
	if g.connDefCfg > 0 {
		g.connDef = g.connDefCfg
	}
	return g
}

// ApplyConsensus 在 Enabled=auto 时用共识 DoSCircuitCreationEnabled / DoSConnectionEnabled（0–1，缺省 0）。
// 显式 0/1 不被共识覆盖。ConnectRate/Burst/Defense 在 torrc 为 0 时跟共识，否则用配置。
func (g *DoSGuard) ApplyConsensus(params map[string]int) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.circOn = dosModeEnabled(g.circMode, params, "DoSCircuitCreationEnabled")
	g.connOn = dosModeEnabled(g.connMode, params, "DoSConnectionEnabled")
	rate := dosConnConnectRateDefault
	burst := dosConnConnectBurstDefault
	if g.connRateCfg > 0 {
		rate = g.connRateCfg
	} else {
		rate = clampDoSParam(params, "DoSConnectionConnectRate", dosConnConnectRateDefault, 1, dosParamMax)
	}
	if g.connBurstCfg > 0 {
		burst = g.connBurstCfg
	} else {
		burst = clampDoSParam(params, "DoSConnectionConnectBurst", dosConnConnectBurstDefault, 1, dosParamMax)
	}
	g.connRate = float64(rate)
	g.connBurst = float64(burst)
	if g.connDefCfg > 0 {
		g.connDef = g.connDefCfg
	} else {
		sec := clampDoSParam(params, "DoSConnectionConnectDefenseTimePeriod",
			int(dosConnConnectDefenseDefault/time.Second), dosConnDefenseMinSec, dosParamMax)
		g.connDef = time.Duration(sec) * time.Second
	}
}

func dosModeEnabled(mode int, params map[string]int, key string) bool {
	switch mode {
	case config.DoSEnabledOn:
		return true
	case config.DoSEnabledOff:
		return false
	default:
		return clampDoSParam(params, key, 0, 0, 1) == 1
	}
}

func clampDoSParam(params map[string]int, key string, def, min, max int) int {
	if params == nil {
		return def
	}
	v, ok := params[key]
	if !ok {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
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
	g := &DoSGuard{
		circOn:    cfg.CircuitEnabled,
		connOn:    cfg.ConnEnabled,
		refuseHop: cfg.RefuseSingleHop,
		minConns:  minC,
		rate:      float64(rate),
		burst:     float64(burst),
		defense:   def,
		maxConns:  maxC,
		connRate:  dosConnConnectRateDefault,
		connBurst: dosConnConnectBurstDefault,
		connDef:   dosConnConnectDefenseDefault,
		ips:       make(map[string]*dosIP),
		lastPurge: time.Now(),
		nowFn:     time.Now,
	}
	if cfg.CircuitEnabled {
		g.circMode = config.DoSEnabledOn
	} else {
		g.circMode = config.DoSEnabledOff
	}
	if cfg.ConnEnabled {
		g.connMode = config.DoSEnabledOn
	} else {
		g.connMode = config.DoSEnabledOff
	}
	return g
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

// OnConnect 在 accept 之后、TLS 之前计数。ConnEnabled 时超过每 IP 上限或连接速率则拒绝。
// 即使连接防御关闭，仍计数，供电路创建 MinConnections 使用。
func (g *DoSGuard) OnConnect(ip string) error {
	if g == nil || ip == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.maybePurgeLocked(now)
	st := g.getLocked(ip)
	if g.connOn {
		if st.conns >= g.maxConns {
			return errDoSConnection
		}
		if now.Before(st.connMarked) {
			return errDoSConnectRate
		}
		g.refillConnLocked(st, now)
		if st.connTokens < 1 {
			st.connMarked = now.Add(g.connDef)
			return errDoSConnectRate
		}
		st.connTokens--
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
	now := g.now()
	if st.conns == 0 && now.After(st.markedUntil) && now.After(st.connMarked) {
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
		now := g.now()
		st = &dosIP{
			tokens:     g.burst,
			lastRefill: now,
			connTokens: g.connBurst,
			connLast:   now,
		}
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

func (g *DoSGuard) refillConnLocked(st *dosIP, now time.Time) {
	elapsed := now.Sub(st.connLast).Seconds()
	if elapsed > 0 {
		st.connTokens += elapsed * g.connRate
		if st.connTokens > g.connBurst {
			st.connTokens = g.connBurst
		}
		st.connLast = now
	}
}

func (g *DoSGuard) maybePurgeLocked(now time.Time) {
	if now.Sub(g.lastPurge) < 10*time.Minute {
		return
	}
	g.lastPurge = now
	for ip, st := range g.ips {
		if st.conns == 0 && now.After(st.markedUntil) && now.After(st.connMarked) && now.Sub(st.lastRefill) > g.defense {
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
