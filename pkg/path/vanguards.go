package path

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// 对照 vanguards-spec Full Vanguards 与 param-spec：
// L2 number=4、lifetime 1–12 天；L3 number=8、lifetime 1–48 小时（max(X,X)）。
const (
	defaultLayer2Count     = 4
	defaultL2LifetimeMin   = 24 * time.Hour
	defaultL2LifetimeMax   = 12 * 24 * time.Hour
	defaultLayer3Count     = 8
	defaultL3LifetimeMin   = time.Hour
	defaultL3LifetimeMax   = 48 * time.Hour
	hsLayer2GuardsStateKey = "GotorHSLayer2Guards"
	hsLayer3GuardsStateKey = "GotorHSLayer3Guards"
)

// torStateFileMu 串行化对 DataDirectory/state 的读改写，避免与 GuardManager 互相覆盖。
var torStateFileMu sync.Mutex

// VanguardConfig 控制 L2/L3 集合与落盘。
type VanguardConfig struct {
	StatePath string
	AvoidDisk bool
	Count     int // L2；<=0 用官方默认 4
	MinLife   time.Duration
	MaxLife   time.Duration
	// L3Count：<0 关闭 L3（仅给 lite 单测）；0 用官方默认 8；>0 显式数量。
	L3Count   int
	L3MinLife time.Duration
	L3MaxLife time.Duration
}

type layerEntry struct {
	FP    string
	Until time.Time
}

// VanguardSet 是客户端 HS 电路的 L2+L3 池（完整 vanguards 的客户端层）。
// 无持久化不得宣称已防护；读写 DataDirectory/state 自有键，不改 Guard 行语义。
// 未做托管侧 intro/rend 固定；不把本实现写成插件级完整 vanguards。
type VanguardSet struct {
	count     int
	minLife   time.Duration
	maxLife   time.Duration
	l3Count   int
	l3MinLife time.Duration
	l3MaxLife time.Duration
	statePath string
	avoidDisk bool
	nowFn     func() time.Time
	mu        sync.Mutex
	layer2    []layerEntry
	layer3    []layerEntry
	logger    *logger.Logger
}

// NewVanguardSet 构造 L2/L3 池。
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
	l3n := cfg.L3Count
	if l3n < 0 {
		l3n = 0
	} else if l3n == 0 {
		l3n = defaultLayer3Count
	}
	l3min, l3max := cfg.L3MinLife, cfg.L3MaxLife
	if l3min <= 0 {
		l3min = defaultL3LifetimeMin
	}
	if l3max < l3min {
		l3max = defaultL3LifetimeMax
	}
	return &VanguardSet{
		count:     n,
		minLife:   minL,
		maxLife:   maxL,
		l3Count:   l3n,
		l3MinLife: l3min,
		l3MaxLife: l3max,
		statePath: cfg.StatePath,
		avoidDisk: cfg.AvoidDisk,
		nowFn:     time.Now,
		logger:    log.Component("vanguards"),
	}
}

func (v *VanguardSet) now() time.Time {
	if v != nil && v.nowFn != nil {
		return v.nowFn()
	}
	return time.Now()
}

// Load 从 state 恢复 L2/L3（缺键则空集合）。
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
	if raw, ok := sf.Get(hsLayer2GuardsStateKey); ok {
		v.layer2 = parseLayerEntries(raw)
	}
	if raw, ok := sf.Get(hsLayer3GuardsStateKey); ok {
		v.layer3 = parseLayerEntries(raw)
	}
	return nil
}

func parseLayerEntries(raw string) []layerEntry {
	var out []layerEntry
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		fp, exp, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		fp = identityToHex(fp)
		sec, err := parseUnixSeconds(exp)
		if err != nil {
			continue
		}
		out = append(out, layerEntry{FP: fp, Until: time.Unix(sec, 0).UTC()})
	}
	return out
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
	l2 := encodeLayerEntries(v.layer2)
	l3 := encodeLayerEntries(v.layer3)
	torStateFileMu.Lock()
	defer torStateFileMu.Unlock()
	return datadir.WithStateFile(v.statePath, "", func(sf *datadir.StateFile) error {
		sf.Set(hsLayer2GuardsStateKey, l2)
		if v.l3Count > 0 {
			sf.Set(hsLayer3GuardsStateKey, l3)
		}
		return nil
	})
}

// Fingerprints 返回当前未过期的 L2 指纹（大写 hex）。
func (v *VanguardSet) Fingerprints() []string {
	return v.liveFingerprints(false)
}

// Layer3Fingerprints 返回当前未过期的 L3 指纹（大写 hex）。
func (v *VanguardSet) Layer3Fingerprints() []string {
	return v.liveFingerprints(true)
}

func (v *VanguardSet) liveFingerprints(l3 bool) []string {
	if v == nil {
		return nil
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	src := v.layer2
	if l3 {
		src = v.layer3
	}
	out := make([]string, 0, len(src))
	for _, e := range src {
		if now.Before(e.Until) {
			out = append(out, e.FP)
		}
	}
	return out
}

// SelectHSPath 选 Guard(L1)→L2→[L3]→target。会按共识刷新集合并在变更时落盘。
// 启用 L3 时为四跳（Path.Middle2）；关闭 L3 时仍为三跳。
func (v *VanguardSet) SelectHSPath(relays []*directory.Relay, target *directory.Relay, persistL1 []string) (*Path, error) {
	if v == nil {
		return nil, fmt.Errorf("vanguard set is nil")
	}
	if target == nil {
		return nil, fmt.Errorf("HS path target is nil")
	}
	byFP := indexRelays(relays)
	v.mu.Lock()
	changed := v.refreshLocked(byFP, persistL1)
	if changed {
		if err := v.persistLocked(); err != nil && v.logger != nil {
			v.logger.Warn("vanguards persist failed", "error", err)
		}
	}
	l2live := v.liveLayerLocked(v.layer2, byFP)
	l3live := v.liveLayerLocked(v.layer3, byFP)
	v.mu.Unlock()

	l1 := pickL1(byFP, persistL1, target, l2live, l3live)
	if l1 == nil {
		return nil, fmt.Errorf("vanguards: no usable L1 guard")
	}
	l2 := pickLayerHop(l2live, []*directory.Relay{l1, target})
	if l2 == nil {
		return nil, fmt.Errorf("vanguards: no usable L2 distinct from L1/target")
	}
	hops := []*directory.Relay{l1, l2, target}
	var l3 *directory.Relay
	if v.l3Count > 0 {
		l3 = pickLayerHop(l3live, []*directory.Relay{l1, l2, target})
		if l3 == nil {
			return nil, fmt.Errorf("vanguards: no usable L3 distinct from L1/L2/target")
		}
		hops = []*directory.Relay{l1, l2, l3, target}
	}
	if hopsShareFamily(hops) {
		return nil, fmt.Errorf("vanguards: hops share family")
	}
	return &Path{Guard: l1, Middle: l2, Middle2: l3, Exit: target}, nil
}

func (v *VanguardSet) refreshLocked(byFP map[string]*directory.Relay, persistL1 []string) bool {
	old := encodeLayerEntries(v.layer2) + "|" + encodeLayerEntries(v.layer3)
	persist := make(map[string]bool)
	for _, raw := range persistL1 {
		if fp := identityToHex(raw); fp != "" {
			persist[fp] = true
		}
	}
	v.layer2 = v.refillLayer(v.layer2, v.count, v.minLife, v.maxLife, false, byFP, persist, nil)
	l2fps := make(map[string]bool, len(v.layer2))
	for _, e := range v.layer2 {
		l2fps[e.FP] = true
	}
	if v.l3Count > 0 {
		v.layer3 = v.refillLayer(v.layer3, v.l3Count, v.l3MinLife, v.l3MaxLife, true, byFP, persist, l2fps)
	} else {
		v.layer3 = nil
	}
	return encodeLayerEntries(v.layer2)+"|"+encodeLayerEntries(v.layer3) != old
}

func (v *VanguardSet) refillLayer(current []layerEntry, want int, minL, maxL time.Duration, maxXX bool, byFP map[string]*directory.Relay, persist, extraExclude map[string]bool) []layerEntry {
	now := v.now()
	kept := make([]layerEntry, 0, want)
	seen := make(map[string]bool)
	for fp := range persist {
		seen[fp] = true
	}
	for fp := range extraExclude {
		seen[fp] = true
	}
	for _, e := range current {
		if !now.Before(e.Until) {
			continue
		}
		fp := identityToHex(e.FP)
		if persist[fp] || extraExclude[fp] {
			continue
		}
		r := byFP[fp]
		if !usableL2(r) {
			continue
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true
		kept = append(kept, layerEntry{FP: fp, Until: e.Until})
	}
	cands := l2Candidates(byFP, seen)
	for len(kept) < want && len(cands) > 0 {
		i := secureIntn(len(cands))
		r := cands[i]
		cands = append(cands[:i], cands[i+1:]...)
		fp := relayFP(r)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		life := v.randLifetimeRange(minL, maxL)
		if maxXX {
			other := v.randLifetimeRange(minL, maxL)
			if other > life {
				life = other
			}
		}
		kept = append(kept, layerEntry{FP: fp, Until: now.Add(life)})
	}
	return kept
}

func (v *VanguardSet) randLifetimeRange(minL, maxL time.Duration) time.Duration {
	span := maxL - minL
	if span <= 0 {
		return minL
	}
	n := secureIntn(int(span/time.Second) + 1)
	return minL + time.Duration(n)*time.Second
}

func (v *VanguardSet) liveLayerLocked(ee []layerEntry, byFP map[string]*directory.Relay) []*directory.Relay {
	now := v.now()
	out := make([]*directory.Relay, 0, len(ee))
	for _, e := range ee {
		if !now.Before(e.Until) {
			continue
		}
		if r := byFP[identityToHex(e.FP)]; usableL2(r) {
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

func normalizeFP(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, " ", "")
	return strings.TrimPrefix(s, "$")
}

// identityToHex 把共识 r 行 base64、C Tor `$`/空格 hex 都收成 40 位大写 hex。
// 不得先 ToUpper：base64 身份区分大小写。
func identityToHex(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimPrefix(s, "$")
	if s == "" {
		return ""
	}
	id, err := directory.DecodeRSAIdentity(s)
	if err != nil || len(id) != 20 {
		return strings.ToUpper(s)
	}
	return strings.ToUpper(hex.EncodeToString(id))
}

func relayFP(r *directory.Relay) string {
	if r == nil {
		return ""
	}
	if fp := identityToHex(r.GetFingerprintHex()); fp != "" {
		return fp
	}
	return identityToHex(r.Fingerprint)
}

func usableL2(r *directory.Relay) bool {
	return r != nil && r.UsableAsGuard()
}

func sameRelayFP(a, b *directory.Relay) bool {
	fa, fb := relayFP(a), relayFP(b)
	return fa != "" && fa == fb
}

func familyConflict(a, b *directory.Relay) bool {
	if a == nil || b == nil {
		return false
	}
	return a.InSameFamily(b) || b.InSameFamily(a)
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

func pickL1(byFP map[string]*directory.Relay, persistL1 []string, target *directory.Relay, l2, l3 []*directory.Relay) *directory.Relay {
	blocked := make(map[string]bool, len(l2)+len(l3))
	for _, r := range l2 {
		blocked[relayFP(r)] = true
	}
	for _, r := range l3 {
		blocked[relayFP(r)] = true
	}
	for _, raw := range persistL1 {
		fp := identityToHex(raw)
		r := byFP[fp]
		if r != nil && r.UsableAsGuard() && !sameRelayFP(r, target) && !familyConflict(r, target) && !blocked[fp] {
			return r
		}
	}
	var cands []*directory.Relay
	for _, r := range byFP {
		if r.UsableAsGuard() && !sameRelayFP(r, target) && !blocked[relayFP(r)] && !familyConflict(r, target) {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		for _, r := range byFP {
			if r.UsableAsGuard() && !sameRelayFP(r, target) && !familyConflict(r, target) {
				cands = append(cands, r)
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	return cands[secureIntn(len(cands))]
}

func pickLayerHop(live []*directory.Relay, exclude []*directory.Relay) *directory.Relay {
	var cands []*directory.Relay
	for _, r := range live {
		skip := false
		for _, x := range exclude {
			if sameRelayFP(r, x) || familyConflict(r, x) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		cands = append(cands, r)
	}
	if len(cands) == 0 {
		return nil
	}
	return cands[secureIntn(len(cands))]
}

func hopsShareFamily(hops []*directory.Relay) bool {
	for i := 0; i < len(hops); i++ {
		for j := i + 1; j < len(hops); j++ {
			if familyConflict(hops[i], hops[j]) {
				return true
			}
		}
	}
	return false
}

func encodeLayerEntries(ee []layerEntry) string {
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
		if fp := identityToHex(g.Fingerprint); fp != "" {
			out = append(out, fp)
		}
	}
	return out
}
