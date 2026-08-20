package relay

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"golang.org/x/crypto/curve25519"
)

// ORPortProber 探测本中继宣告的 ORPort 是否能从电路对端连上。
// 成功只表示本端 self-test 通过，不等于权威投票 Running，更不等于进共识。
type ORPortProber func(ctx context.Context) error

// ReachabilityConfig 对照 C Tor src/feature/relay/selftest.c。
type ReachabilityConfig struct {
	AssumeReachable bool
	DisableNetwork  bool
	Address         string
	ORPort          int
	Publish         bool
	RetryInterval   time.Duration // 默认 20s（C Tor reachability callback 量级）
	ComplaintAfter  time.Duration // 默认 20m（TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT）
}

const (
	defaultReachRetry     = 20 * time.Second
	defaultReachComplaint = 20 * time.Minute
)

// Reachability 管 ORPort self-test 与描述符发布门闩。
//
// 对照 C Tor selftest.c / router.c：
//   - AssumeReachable 或 DisableNetwork：不探测。
//   - AssumeReachable 且未 DisableNetwork：视为本端认为可达，允许发布。
//   - 否则：未成功前不得发布；成功后才允许 POST 描述符。
//   - 失败只打日志并重试，绝不把成功写成 Running / 进共识。
type Reachability struct {
	cfg   ReachabilityConfig
	probe ORPortProber
	log   *logger.Logger

	mu          sync.Mutex
	reachable   bool
	attempts    int
	lastErr     error
	startedAt   time.Time
	complained  bool
	lastCompl   time.Time
	onReachable func()
	cancel      context.CancelFunc
	stopCh      chan struct{}
	stoppedCh   chan struct{}
	running     bool
}

// NewReachability 创建 self-test 状态机。probe 可稍后 SetProber。
func NewReachability(cfg ReachabilityConfig, log *logger.Logger) *Reachability {
	if log == nil {
		log = logger.NewDefault()
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = defaultReachRetry
	}
	if cfg.ComplaintAfter <= 0 {
		cfg.ComplaintAfter = defaultReachComplaint
	}
	return &Reachability{
		cfg:    cfg,
		log:    log.Component("selftest"),
		stopCh: make(chan struct{}),
	}
}

// SetProber 注入探测函数（生产为经客户端电路 EXTEND 到本 ORPort）。
func (r *Reachability) SetProber(p ORPortProber) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probe = p
}

// SetOnReachable 在首次判定可达（含 AssumeReachable）后回调，用于立刻触发发布。
func (r *Reachability) SetOnReachable(fn func()) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onReachable = fn
}

// ShouldProbe 对照 router_should_check_reachability：要发布、未假定可达、网络未关、尚未成功。
func (r *Reachability) ShouldProbe() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.shouldProbeLocked()
}

func (r *Reachability) shouldProbeLocked() bool {
	if !r.cfg.Publish || r.cfg.AssumeReachable || r.cfg.DisableNetwork || r.reachable {
		return false
	}
	if r.cfg.Address == "" || r.cfg.ORPort <= 0 {
		return false
	}
	return true
}

// CanPublish 对照 ready_to_publish / check_whether_orport_reachable。
// DisableNetwork 时不发布（比 C Tor 模块内「视为可达」更严，避免空发）。
func (r *Reachability) CanPublish() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.DisableNetwork || !r.cfg.Publish {
		return false
	}
	if r.cfg.Address == "" || r.cfg.ORPort <= 0 {
		return false
	}
	return r.reachable || r.cfg.AssumeReachable
}

// ReachabilityStatus 是可测试的快照。没有 Running / 共识字段。
type ReachabilityStatus struct {
	Reachable  bool
	Assumed    bool
	Attempts   int
	LastError  string
	CanPublish bool
}

// Status 返回当前 self-test 快照。
func (r *Reachability) Status() ReachabilityStatus {
	if r == nil {
		return ReachabilityStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := ReachabilityStatus{
		Reachable:  r.reachable,
		Assumed:    r.cfg.AssumeReachable,
		Attempts:   r.attempts,
		CanPublish: !r.cfg.DisableNetwork && r.cfg.Publish && r.cfg.Address != "" && r.cfg.ORPort > 0 && (r.reachable || r.cfg.AssumeReachable),
	}
	if r.lastErr != nil {
		st.LastError = r.lastErr.Error()
	}
	return st
}

// RunOnce 执行一次探测。AssumeReachable / 已成功则直接返回。
func (r *Reachability) RunOnce(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("reachability is nil")
	}
	r.mu.Lock()
	if r.cfg.AssumeReachable && !r.cfg.DisableNetwork {
		already := r.reachable
		r.reachable = true
		cb := r.onReachable
		r.mu.Unlock()
		if !already {
			r.log.Info("AssumeReachable is set; skipping ORPort circuit self-test (not a real probe; authorities still test independently)")
			if cb != nil {
				cb()
			}
		}
		return nil
	}
	if !r.shouldProbeLocked() {
		r.mu.Unlock()
		return nil
	}
	probe := r.probe
	r.mu.Unlock()
	if probe == nil {
		err := fmt.Errorf("ORPort self-test has no circuit prober")
		r.recordFailure(err)
		return err
	}

	r.log.Info("testing reachability of ORPort via circuit (C Tor PURPOSE_TESTING analog)")
	err := probe(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.recordFailure(err)
		return err
	}
	r.recordSuccess()
	return nil
}

func (r *Reachability) recordSuccess() {
	r.mu.Lock()
	already := r.reachable
	r.reachable = true
	r.lastErr = nil
	r.attempts++
	cb := r.onReachable
	r.mu.Unlock()
	if already {
		return
	}
	// 对齐 C Tor router_orport_found_reachable 的 notice，但不写 Running。
	r.log.Info("self-testing indicates ORPort is reachable from the outside; publishing server descriptor")
	if cb != nil {
		cb()
	}
}

func (r *Reachability) recordFailure(err error) {
	now := time.Now()
	r.mu.Lock()
	r.attempts++
	r.lastErr = err
	if r.startedAt.IsZero() {
		r.startedAt = now
	}
	elapsed := now.Sub(r.startedAt)
	shouldComplain := elapsed >= r.cfg.ComplaintAfter && (!r.complained || now.Sub(r.lastCompl) >= r.cfg.ComplaintAfter)
	if shouldComplain {
		r.complained = true
		r.lastCompl = now
	}
	attempts := r.attempts
	r.mu.Unlock()

	r.log.Info("ORPort self-test failed; descriptor will not be published yet",
		"attempt", attempts, "error", err)
	if shouldComplain {
		r.log.Warn("ORPort reachability not confirmed after repeated self-tests; still not treating this as Running")
	}
}

// Start 在后台重试探测，直到成功或 Stop。已假定可达时只触发一次回调。
func (r *Reachability) Start(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("reachability is nil")
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("reachability self-test already running")
	}
	r.running = true
	r.startedAt = time.Now()
	r.stoppedCh = make(chan struct{})
	loopCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()

	go r.loop(loopCtx)
	return nil
}

func (r *Reachability) loop(ctx context.Context) {
	defer close(r.stoppedCh)

	if err := r.RunOnce(ctx); err == nil && !r.ShouldProbe() {
		return
	}

	ticker := time.NewTicker(r.cfg.RetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := r.RunOnce(ctx); err == nil && !r.ShouldProbe() {
				return
			}
		case <-r.stopCh:
			r.log.Info("ORPort self-test stopping")
			return
		case <-ctx.Done():
			r.log.Info("ORPort self-test context cancelled")
			return
		}
	}
}

// Stop 结束后台探测。可重复调用。
func (r *Reachability) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	close(r.stopCh)
	if r.stoppedCh != nil {
		<-r.stoppedCh
	}
}

// TestingHop 把本中继身份编成 EXTEND2 末跳（C Tor extend_info_from_router(me)）。
// 不含共识 Flags；不得当作已 Running。
func (k *RelayKeys) TestingHop(nickname, address string, orPort int) *directory.Relay {
	if k == nil || address == "" || orPort <= 0 {
		return nil
	}
	ntorPub := ntorPublicFromPrivate(k.NtorOnionKey)
	if len(ntorPub) != 32 {
		return nil
	}
	rsaID := k.RSANodeID()
	if len(rsaID) != 20 {
		return nil
	}
	ed := append([]byte(nil), k.Ed25519Public...)
	if len(ed) != 32 {
		return nil
	}
	nick := nickname
	if nick == "" {
		nick = "Unnamed"
	}
	return &directory.Relay{
		Nickname:       nick,
		Fingerprint:    k.Fingerprint(),
		FingerprintHex: k.Fingerprint(),
		Address:        address,
		ORPort:         orPort,
		RSAIdentity:    rsaID,
		IdentityKey:    ed,
		NtorOnionKey:   ntorPub,
	}
}

func ntorPublicFromPrivate(priv []byte) []byte {
	if len(priv) != 32 {
		return nil
	}
	var pub, p [32]byte
	copy(p[:], priv)
	curve25519.ScalarBaseMult(&pub, &p)
	return pub[:]
}
