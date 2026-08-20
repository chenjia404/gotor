package path

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// vanguards-lite（C Tor 默认 / Arti）：仅固定 L2，无 L3。
// 对照 vanguards-spec「Vanguards-lite」与 C Tor guard-hs-l2-number=4、
// lifetime-min=1d / lifetime-max=12d。
const (
	defaultLayer2Count     = 4
	defaultL2LifetimeMin   = 24 * time.Hour
	defaultL2LifetimeMax   = 12 * 24 * time.Hour
	hsLayer2GuardsStateKey = "GotorHSLayer2Guards"
)

// torStateFileMu 串行化对 DataDirectory/state 的读改写，避免与 GuardManager 互相覆盖。
var torStateFileMu sync.Mutex

// VanguardConfig 控制 L2 集合与落盘。
type VanguardConfig struct {
	StatePath string
	AvoidDisk bool
	Count     int
	MinLife   time.Duration
	MaxLife   time.Duration
}

type layer2Entry struct {
	FP    string
	Until time.Time
}

// VanguardSet 是客户端 HS 电路的 vanguards-lite L2 池。
// 无持久化不得宣称已防护；本集合读写 DataDirectory/state 的自有键，不改 Guard 行语义。
type VanguardSet struct {
	count     int
	minLife   time.Duration
	maxLife   time.Duration
	statePath string
	avoidDisk bool
	nowFn     func() time.Time
	mu        sync.Mutex
	layer2    []layer2Entry
	logger    *logger.Logger
}

// NewVanguardSet 构造 L2 池。Count<=0 用官方默认 4。
func NewVanguardSet(cfg VanguardConfig, log *logger.Logger) *VanguardSet {
	if log == nil {
		log = logger.NewDefault()
	}
	n := cfg.Count
	if n <= 0 {
		n = defaultLayer2Count
	}
	minL, maxL := cfg.MinLife, cfg.MaxLife
	if minL <= 0 {
		minL = defaultL2LifetimeMin
	}
	if maxL < minL {
		maxL = defaultL2LifetimeMax
	}
	return &VanguardSet{
		count:     n,
		minLife:   minL,
		maxLife:   maxL,
		statePath: cfg.StatePath,
		avoidDisk: cfg.AvoidDisk,
		nowFn:     time.Now,
		logger:    log.Component("vanguards-lite"),
	}
}

func (v *VanguardSet) now() time.Time {
	if v != nil && v.nowFn != nil {
		return v.nowFn()
	}
	return time.Now()
}

// Load 从 state 恢复 L2（缺键则空集合）。
// 锁顺序必须与 persistLocked 一致：先 v.mu 再 torStateFileMu，避免死锁或用过期快照覆盖内存。
func (v *VanguardSet) Load() error {
	if v == nil || v.statePath == "" {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	torStateFileMu.Lock()
	sf, err := datadir.LoadState(v.statePath)
	torStateFileMu.Unlock()
	if err != nil {
		return err
	}
	raw, ok := sf.Get(hsLayer2GuardsStateKey)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []layer2Entry
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		fp, exp, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		fp = strings.ToUpper(strings.TrimSpace(fp))
		sec, err := parseUnixSeconds(exp)
		if err != nil {
			continue
		}
		out = append(out, layer2Entry{FP: fp, Until: time.Unix(sec, 0).UTC()})
	}
	v.layer2 = out
	return nil
}

func parseUnixSeconds(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not unix seconds")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

func (v *VanguardSet) persistLocked() error {
	if v.avoidDisk || v.statePath == "" {
		return nil
	}
	val := encodeLayer2(v.layer2)
	torStateFileMu.Lock()
	defer torStateFileMu.Unlock()
	return datadir.WithStateFile(v.statePath, "", func(sf *datadir.StateFile) error {
		sf.Set(hsLayer2GuardsStateKey, val)
		return nil
	})
}

// Fingerprints 返回当前未过期的 L2 指纹（大写 hex）。
func (v *VanguardSet) Fingerprints() []string {
	if v == nil {
		return nil
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.layer2))
	for _, e := range v.layer2 {
		if now.Before(e.Until) {
			out = append(out, e.FP)
		}
	}
	return out
}

// SelectHSPath 选 Guard(L1)→L2→target。会按共识刷新 L2 并在变更时落盘。
func (v *VanguardSet) SelectHSPath(relays []*directory.Relay, target *directory.Relay, persistL1 []string) (*Path, error) {
	if v == nil {
		return nil, fmt.Errorf("vanguard set is nil")
	}
	if target == nil {
		return nil, fmt.Errorf("HS path target is nil")
	}
	byFP := indexRelays(relays)
	v.mu.Lock()
	changed := v.refreshLocked(byFP)
	if changed {
		if err := v.persistLocked(); err != nil && v.logger != nil {
			v.logger.Warn("vanguards-lite persist failed", "error", err)
		}
	}
	l2live := v.liveRelaysLocked(byFP)
	v.mu.Unlock()

	l1 := pickL1(byFP, persistL1, target, l2live)
	if l1 == nil {
		return nil, fmt.Errorf("vanguards-lite: no usable L1 guard")
	}
	l2 := pickL2(l2live, l1, target)
	if l2 == nil {
		return nil, fmt.Errorf("vanguards-lite: no usable L2 distinct from L1/target")
	}
	return &Path{Guard: l1, Middle: l2, Exit: target}, nil
}

func (v *VanguardSet) refreshLocked(byFP map[string]*directory.Relay) bool {
	now := v.now()
	old := encodeLayer2(v.layer2)
	kept := make([]layer2Entry, 0, v.count)
	seen := make(map[string]bool)
	for _, e := range v.layer2 {
		if !now.Before(e.Until) {
			continue
		}
		r := byFP[e.FP]
		// 当前电路目标碰巧是某 L2 时只在本条选路避开，不得从全局集合剔除。
		if !usableL2(r) {
			continue
		}
		if seen[e.FP] {
			continue
		}
		seen[e.FP] = true
		kept = append(kept, e)
	}
	cands := l2Candidates(byFP, seen)
	for len(kept) < v.count && len(cands) > 0 {
		i := secureIntn(len(cands))
		r := cands[i]
		cands = append(cands[:i], cands[i+1:]...)
		fp := relayFP(r)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		kept = append(kept, layer2Entry{FP: fp, Until: now.Add(v.randLifetime())})
	}
	v.layer2 = kept
	return encodeLayer2(v.layer2) != old
}

func (v *VanguardSet) randLifetime() time.Duration {
	span := v.maxLife - v.minLife
	if span <= 0 {
		return v.minLife
	}
	n := secureIntn(int(span/time.Second) + 1)
	return v.minLife + time.Duration(n)*time.Second
}

func (v *VanguardSet) liveRelaysLocked(byFP map[string]*directory.Relay) []*directory.Relay {
	now := v.now()
	out := make([]*directory.Relay, 0, len(v.layer2))
	for _, e := range v.layer2 {
		if !now.Before(e.Until) {
			continue
		}
		if r := byFP[e.FP]; usableL2(r) {
			out = append(out, r)
		}
	}
	return out
}

func indexRelays(relays []*directory.Relay) map[string]*directory.Relay {
	m := make(map[string]*directory.Relay, len(relays))
	for _, r := range relays {
		if r == nil {
			continue
		}
		if fp := relayFP(r); fp != "" {
			m[fp] = r
		}
	}
	return m
}

func relayFP(r *directory.Relay) string {
	if r == nil {
		return ""
	}
	fp := strings.ToUpper(r.GetFingerprintHex())
	if fp == "" {
		fp = strings.ToUpper(r.Fingerprint)
	}
	return fp
}

func usableL2(r *directory.Relay) bool {
	return r != nil && r.UsableAsGuard()
}

func sameRelayFP(a, b *directory.Relay) bool {
	fa, fb := relayFP(a), relayFP(b)
	return fa != "" && fa == fb
}

func l2Candidates(byFP map[string]*directory.Relay, exclude map[string]bool) []*directory.Relay {
	out := make([]*directory.Relay, 0, len(byFP))
	for fp, r := range byFP {
		if exclude[fp] || !usableL2(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func pickL1(byFP map[string]*directory.Relay, persistL1 []string, target *directory.Relay, l2 []*directory.Relay) *directory.Relay {
	inL2 := make(map[string]bool, len(l2))
	for _, r := range l2 {
		inL2[relayFP(r)] = true
	}
	for _, raw := range persistL1 {
		fp := strings.ToUpper(strings.TrimSpace(raw))
		r := byFP[fp]
		if r != nil && r.UsableAsGuard() && !sameRelayFP(r, target) {
			return r
		}
	}
	var cands []*directory.Relay
	for _, r := range byFP {
		if r.UsableAsGuard() && !sameRelayFP(r, target) && !inL2[relayFP(r)] {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		for _, r := range byFP {
			if r.UsableAsGuard() && !sameRelayFP(r, target) {
				cands = append(cands, r)
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	return cands[secureIntn(len(cands))]
}

func pickL2(live []*directory.Relay, l1, target *directory.Relay) *directory.Relay {
	var cands []*directory.Relay
	for _, r := range live {
		if sameRelayFP(r, l1) || sameRelayFP(r, target) {
			continue
		}
		if l1 != nil && (l1.InSameFamily(r) || r.InSameFamily(target)) {
			continue
		}
		cands = append(cands, r)
	}
	if len(cands) == 0 {
		for _, r := range live {
			if !sameRelayFP(r, l1) && !sameRelayFP(r, target) {
				cands = append(cands, r)
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	return cands[secureIntn(len(cands))]
}

func encodeLayer2(ee []layer2Entry) string {
	parts := make([]string, 0, len(ee))
	for _, e := range ee {
		parts = append(parts, fmt.Sprintf("%s=%d", e.FP, e.Until.UTC().Unix()))
	}
	return strings.Join(parts, ",")
}

func secureIntn(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// PersistL1Fingerprints 把 GuardManager 的入口指纹抽出给 HS 选路。
func PersistL1Fingerprints(gm *GuardManager) []string {
	if gm == nil {
		return nil
	}
	gs := gm.GetGuards()
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		if g.Fingerprint != "" {
			out = append(out, g.Fingerprint)
		}
	}
	return out
}
