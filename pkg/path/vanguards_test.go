package path

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/directory"
)

func vgRelay(fp, nick string) *directory.Relay {
	return &directory.Relay{
		Nickname:    nick,
		Fingerprint: strings.ToUpper(fp),
		Address:     "198.51.100." + fp[len(fp)-1:],
		ORPort:      9001,
		Flags:       []string{"Running", "Valid", "Guard", "Fast", "Stable"},
	}
}

func vgPool() []*directory.Relay {
	return []*directory.Relay{
		vgRelay("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "G1"),
		vgRelay("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "G2"),
		vgRelay("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "G3"),
		vgRelay("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "G4"),
		vgRelay("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", "G5"),
		vgRelay("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "G6"),
		vgRelay("1111111111111111111111111111111111111111", "Target"),
	}
}

func TestVanguardSetFillsFourAndSticks(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: 2 * time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgPool()
	target := pool[len(pool)-1]
	p1, err := v.SelectHSPath(pool, target, []string{pool[0].Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if p1.Guard.Fingerprint != pool[0].Fingerprint {
		t.Fatalf("L1 应优先持久入口，got %s", p1.Guard.Nickname)
	}
	if p1.Exit != target {
		t.Fatal("末跳必须是目标")
	}
	if p1.Middle == nil || p1.Middle.Fingerprint == p1.Guard.Fingerprint || p1.Middle.Fingerprint == target.Fingerprint {
		t.Fatal("L2 须与 L1/目标不同")
	}
	if containsFP(v.Fingerprints(), pool[0].Fingerprint) {
		t.Fatal("新填 L2 不得含持久 L1")
	}
	fps := v.Fingerprints()
	if len(fps) != 4 {
		t.Fatalf("L2 数 %d, want 4", len(fps))
	}
	p2, err := v.SelectHSPath(pool, target, []string{pool[0].Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if p2.Middle.Fingerprint != p1.Middle.Fingerprint && !containsFP(fps, p2.Middle.Fingerprint) {
		t.Fatal("第二次选路 L2 必须仍在固定集合内")
	}
	got := append([]string{}, fps...)
	p3, _ := v.SelectHSPath(pool, target, []string{pool[0].Fingerprint})
	if !containsFP(got, p3.Middle.Fingerprint) {
		t.Fatal("随机多跳不得冒充 vanguards：L2 必须来自已固定集合")
	}
}

func TestVanguardSetPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, datadir.StateFileName)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	v := NewVanguardSet(VanguardConfig{StatePath: state, L3Count: -1, Count: 4, MinLife: 24 * time.Hour, MaxLife: 24 * time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	first := v.Fingerprints()
	if len(first) != 4 {
		t.Fatalf("want 4, got %v", first)
	}
	again := NewVanguardSet(VanguardConfig{StatePath: state, L3Count: -1, Count: 4}, nil)
	again.nowFn = func() time.Time { return now }
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	loaded := again.Fingerprints()
	if len(loaded) != 4 {
		t.Fatalf("reload %v", loaded)
	}
	for _, fp := range first {
		if !containsFP(loaded, fp) {
			t.Fatalf("missing %s after reload %v", fp, loaded)
		}
	}
	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), hsLayer2GuardsStateKey) {
		t.Fatal("state 应含 GotorHSLayer2Guards")
	}
	if strings.Contains(string(raw), "Guard rsa_id") && !strings.Contains(string(raw), hsLayer2GuardsStateKey) {
		t.Fatal("不得改写官方 Guard 行语义")
	}
}

func TestVanguardAndGuardConcurrentState(t *testing.T) {
	dir := t.TempDir()
	gm, err := NewGuardManager(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := vgPool()
	v := NewVanguardSet(VanguardConfig{
		StatePath: filepath.Join(dir, datadir.StateFileName),
		L3Count:   -1,
		Count:     4,
		MinLife:   time.Hour,
		MaxLife:   time.Hour,
	}, nil)
	done := make(chan error, 2)
	go func() {
		for i := 0; i < 20; i++ {
			if err := gm.AddGuard(pool[i%3]); err != nil {
				done <- err
				return
			}
			if err := gm.Save(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, datadir.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	txt := string(raw)
	if !strings.Contains(txt, hsLayer2GuardsStateKey) {
		t.Fatal("并发写后丢掉 L2 键")
	}
	if !strings.Contains(txt, "Guard") {
		t.Fatal("并发写后丢掉官方 Guard 行")
	}
}

func TestVanguardAndGuardShareStateFile(t *testing.T) {
	dir := t.TempDir()
	gm, err := NewGuardManager(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := vgPool()
	if err := gm.AddGuard(pool[0]); err != nil {
		t.Fatal(err)
	}
	if err := gm.Save(); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, datadir.StateFileName)
	v := NewVanguardSet(VanguardConfig{StatePath: state, L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	if err := gm.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	txt := string(raw)
	if !strings.Contains(txt, hsLayer2GuardsStateKey) {
		t.Fatal("Guard 再写后不得丢掉 L2 键")
	}
	if !strings.Contains(txt, strings.ToUpper(pool[0].Fingerprint)) {
		t.Fatal("L2 写入后不得丢掉 Guard 行")
	}
	again := NewVanguardSet(VanguardConfig{StatePath: state, L3Count: -1, Count: 4}, nil)
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	if len(again.Fingerprints()) != 4 {
		t.Fatalf("reload L2 %v", again.Fingerprints())
	}
}

func TestVanguardSetAvoidDisk(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, datadir.StateFileName)
	v := NewVanguardSet(VanguardConfig{StatePath: state, AvoidDisk: true, L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("AvoidDiskWrites 时不得写 state")
	}
}

func TestVanguardSetExpiresAndRefills(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, datadir.StateFileName)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	v := NewVanguardSet(VanguardConfig{StatePath: state, L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	oldUntil := now.Add(time.Hour).Unix()
	now = now.Add(2 * time.Hour)
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	after := v.Fingerprints()
	if len(after) != 4 {
		t.Fatalf("过期后应补满 4，got %v", after)
	}
	sf, err := datadir.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := sf.Get(hsLayer2GuardsStateKey)
	if !ok || raw == "" {
		t.Fatal("过期重填后应落盘新寿命")
	}
	for _, tok := range strings.Split(raw, ",") {
		_, exp, found := strings.Cut(tok, "=")
		if !found {
			t.Fatalf("坏条目 %q", tok)
		}
		sec, err := parseUnixSeconds(exp)
		if err != nil {
			t.Fatal(err)
		}
		if sec <= oldUntil {
			t.Fatalf("过期条目未换新寿命: %s", tok)
		}
	}
}

func TestVanguardSetDropsL2WhenItBecomesPersistL1(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	l2 := append([]string{}, v.Fingerprints()...)
	if len(l2) != 4 {
		t.Fatalf("%v", l2)
	}
	targetFP := strings.ToUpper(pool[6].Fingerprint)
	promoted := ""
	for _, fp := range l2 {
		if fp != targetFP {
			promoted = fp
			break
		}
	}
	if promoted == "" {
		t.Fatal("L2 除目标外应有可晋升入口")
	}
	p, err := v.SelectHSPath(pool, pool[6], []string{promoted})
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Fingerprint != promoted {
		t.Fatalf("晋升入口应作 L1，got %s persist=%s beforeL2=%v afterL2=%v", p.Guard.Fingerprint, promoted, l2, v.Fingerprints())
	}
	if containsFP(v.Fingerprints(), promoted) {
		t.Fatal("已是入口的节点必须退出 L2")
	}
	if len(v.Fingerprints()) != 4 {
		t.Fatalf("退出后应补满 L2，got %v", v.Fingerprints())
	}
}

func TestVanguardSetKeepsL2WhenTargetMatches(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	before := append([]string{}, v.Fingerprints()...)
	if len(before) != 4 {
		t.Fatalf("%v", before)
	}
	// 把某个已固定 L2 当作本条电路目标，不得从全局集合剔除。
	var hit *directory.Relay
	for _, r := range pool {
		if containsFP(before, r.Fingerprint) {
			hit = r
			break
		}
	}
	if hit == nil {
		t.Fatal("no L2 in pool")
	}
	if _, err := v.SelectHSPath(pool, hit, nil); err != nil {
		t.Fatal(err)
	}
	after := v.Fingerprints()
	if len(after) != 4 {
		t.Fatalf("target=L2 后集合被收缩: %v → %v", before, after)
	}
	for _, fp := range before {
		if !containsFP(after, fp) {
			t.Fatalf("L2 %s 因当前目标被踢出集合", fp)
		}
	}
}

func TestVanguardSetAcceptsBase64PersistL1(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	hexFP := pool[0].Fingerprint
	raw, err := hex.DecodeString(hexFP)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawStdEncoding.EncodeToString(raw)
	pool[0].FingerprintHex = hexFP
	pool[0].Fingerprint = b64
	p, err := v.SelectHSPath(pool, pool[6], []string{b64})
	if err != nil {
		t.Fatal(err)
	}
	if identityToHex(p.Guard.GetFingerprintHex()) != hexFP {
		t.Fatalf("共识 r 行 base64 入口应对上 hex L2 键，got %s", p.Guard.Nickname)
	}
	if containsFP(v.Fingerprints(), hexFP) {
		t.Fatal("base64 入口规范化后仍应从 L2 剔除")
	}
}

func TestVanguardSetAcceptsSpacedPersistL1(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	raw := pool[0].Fingerprint
	var b strings.Builder
	for i := 0; i < len(raw); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		b.WriteString(raw[i:end])
	}
	p, err := v.SelectHSPath(pool, pool[6], []string{"$" + b.String()})
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Fingerprint != pool[0].Fingerprint {
		t.Fatalf("C Tor 空格/$ 指纹应对上共识 hex，got %s", p.Guard.Nickname)
	}
	if containsFP(v.Fingerprints(), pool[0].Fingerprint) {
		t.Fatal("规范化后的入口仍应从 L2 剔除")
	}
}

func TestVanguardSetRejectsL1SameFamilyAsTarget(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	fam := []string{"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	pool[0].FamilyIDs = fam
	pool[6].FamilyIDs = fam
	p, err := v.SelectHSPath(pool, pool[6], []string{pool[0].Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Fingerprint == pool[0].Fingerprint {
		t.Fatal("不得用与目标同家族的持久入口")
	}
	if p.Guard.InSameFamily(p.Exit) || p.Middle.InSameFamily(p.Exit) || p.Guard.InSameFamily(p.Middle) {
		t.Fatal("三跳不得同家族")
	}
}

func TestVanguardSetFailsWhenAllShareFamilyWithTarget(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	fam := []string{"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for _, r := range pool {
		r.FamilyIDs = fam
	}
	if _, err := v.SelectHSPath(pool, pool[6], []string{pool[0].Fingerprint}); err == nil {
		t.Fatal("全体与目标同家族时应失败关闭，不得成路")
	}
}

func TestVanguardSetDoesNotPickTargetAsL2(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{L3Count: -1, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	target := pool[6]
	for i := 0; i < 8; i++ {
		p, err := v.SelectHSPath(pool, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Middle.Fingerprint == target.Fingerprint || p.Guard.Fingerprint == target.Fingerprint {
			t.Fatal("L1/L2 不得是目标")
		}
	}
}

func containsFP(list []string, fp string) bool {
	fp = strings.ToUpper(fp)
	for _, x := range list {
		if strings.ToUpper(x) == fp {
			return true
		}
	}
	return false
}

func vgWidePool() []*directory.Relay {
	out := make([]*directory.Relay, 0, 16)
	for i := 0; i < 16; i++ {
		fp := strings.Repeat(fmt.Sprintf("%02X", i), 20)
		nick := fmt.Sprintf("N%d", i)
		if i == 15 {
			nick = "Target"
		}
		out = append(out, vgRelay(fp, nick))
	}
	return out
}

func TestVanguardSetFillsL3FourHopAndSticks(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	v := NewVanguardSet(VanguardConfig{Count: 4, L3Count: 8, MinLife: time.Hour, MaxLife: 2 * time.Hour, L3MinLife: time.Hour, L3MaxLife: 2 * time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgWidePool()
	target := pool[len(pool)-1]
	p1, err := v.SelectHSPath(pool, target, []string{pool[0].Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if p1.Guard.Fingerprint != pool[0].Fingerprint {
		t.Fatalf("L1 应优先持久入口，got %s", p1.Guard.Nickname)
	}
	if p1.Middle2 == nil {
		t.Fatal("启用 L3 必须是四跳")
	}
	if p1.Exit != target {
		t.Fatal("末跳必须是目标")
	}
	seen := map[string]bool{
		p1.Guard.Fingerprint:   true,
		p1.Middle.Fingerprint:  true,
		p1.Middle2.Fingerprint: true,
		p1.Exit.Fingerprint:    true,
	}
	if len(seen) != 4 {
		t.Fatal("L1/L2/L3/目标必须互异")
	}
	l2 := v.Fingerprints()
	l3 := v.Layer3Fingerprints()
	if len(l2) != 4 {
		t.Fatalf("L2 数 %d", len(l2))
	}
	if len(l3) != 8 {
		t.Fatalf("L3 数 %d, want 8", len(l3))
	}
	if containsFP(l2, pool[0].Fingerprint) || containsFP(l3, pool[0].Fingerprint) {
		t.Fatal("L2/L3 不得含持久 L1")
	}
	for _, fp := range l2 {
		if containsFP(l3, fp) {
			t.Fatalf("L2 与 L3 重叠 %s", fp)
		}
	}
	if !containsFP(l2, p1.Middle.Fingerprint) {
		t.Fatal("第二跳必须来自 L2 池")
	}
	if !containsFP(l3, p1.Middle2.Fingerprint) {
		t.Fatal("第三跳必须来自 L3 池")
	}
	p2, err := v.SelectHSPath(pool, target, []string{pool[0].Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if !containsFP(l2, p2.Middle.Fingerprint) || !containsFP(l3, p2.Middle2.Fingerprint) {
		t.Fatal("第二次选路仍须落在固定 L2/L3 集合内")
	}
}

func TestVanguardSetPersistsLayer3(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, datadir.StateFileName)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	v := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4, L3Count: 8, MinLife: 24 * time.Hour, MaxLife: 24 * time.Hour, L3MinLife: time.Hour, L3MaxLife: time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgWidePool()
	if _, err := v.SelectHSPath(pool, pool[15], nil); err != nil {
		t.Fatal(err)
	}
	first := v.Layer3Fingerprints()
	if len(first) != 8 {
		t.Fatalf("want 8 L3, got %v", first)
	}
	again := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4, L3Count: 8}, nil)
	again.nowFn = func() time.Time { return now }
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	loaded := again.Layer3Fingerprints()
	if len(loaded) != 8 {
		t.Fatalf("reload L3 %v", loaded)
	}
	for _, fp := range first {
		if !containsFP(loaded, fp) {
			t.Fatalf("missing L3 %s after reload", fp)
		}
	}
	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	txt := string(raw)
	if !strings.Contains(txt, hsLayer3GuardsStateKey) {
		t.Fatal("state 应含 GotorHSLayer3Guards")
	}
	if !strings.Contains(txt, hsLayer2GuardsStateKey) {
		t.Fatal("写 L3 不得丢掉 L2 键")
	}
}

func TestVanguardSetDropsL3WhenItBecomesPersistL1(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, L3Count: 8, MinLife: time.Hour, MaxLife: time.Hour, L3MinLife: time.Hour, L3MaxLife: time.Hour}, nil)
	pool := vgWidePool()
	if _, err := v.SelectHSPath(pool, pool[15], nil); err != nil {
		t.Fatal(err)
	}
	l3 := append([]string{}, v.Layer3Fingerprints()...)
	targetFP := strings.ToUpper(pool[15].Fingerprint)
	promoted := ""
	for _, fp := range l3 {
		if fp != targetFP {
			promoted = fp
			break
		}
	}
	if promoted == "" {
		t.Fatal("L3 除目标外应有可晋升入口")
	}
	p, err := v.SelectHSPath(pool, pool[15], []string{promoted})
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Fingerprint != promoted {
		t.Fatalf("晋升入口应作 L1，got %s", p.Guard.Nickname)
	}
	if containsFP(v.Layer3Fingerprints(), promoted) {
		t.Fatal("已是入口的节点必须退出 L3")
	}
	if len(v.Layer3Fingerprints()) != 8 {
		t.Fatalf("退出后应补满 L3，got %v", v.Layer3Fingerprints())
	}
}

func TestVanguardSetKeepsL3WhenTargetMatches(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, L3Count: 8, MinLife: time.Hour, MaxLife: time.Hour, L3MinLife: time.Hour, L3MaxLife: time.Hour}, nil)
	pool := vgWidePool()
	if _, err := v.SelectHSPath(pool, pool[15], nil); err != nil {
		t.Fatal(err)
	}
	before := append([]string{}, v.Layer3Fingerprints()...)
	var hit *directory.Relay
	for _, r := range pool {
		if containsFP(before, r.Fingerprint) {
			hit = r
			break
		}
	}
	if hit == nil {
		t.Fatal("no L3 in pool")
	}
	if _, err := v.SelectHSPath(pool, hit, nil); err != nil {
		t.Fatal(err)
	}
	after := v.Layer3Fingerprints()
	if len(after) != 8 {
		t.Fatalf("target=L3 后集合被收缩: %v → %v", before, after)
	}
	for _, fp := range before {
		if !containsFP(after, fp) {
			t.Fatalf("L3 %s 因当前目标被踢出集合", fp)
		}
	}
}

func TestVanguardSetFourHopRejectsSharedFamily(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, L3Count: 8, MinLife: time.Hour, MaxLife: time.Hour, L3MinLife: time.Hour, L3MaxLife: time.Hour}, nil)
	pool := vgWidePool()
	fam := []string{"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for _, r := range pool {
		r.FamilyIDs = fam
	}
	if _, err := v.SelectHSPath(pool, pool[15], []string{pool[0].Fingerprint}); err == nil {
		t.Fatal("四跳全体同家族时应失败关闭")
	}
}

func TestVanguardSetDoesNotPickTargetAsL3(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, L3Count: 8, MinLife: time.Hour, MaxLife: time.Hour, L3MinLife: time.Hour, L3MaxLife: time.Hour}, nil)
	pool := vgWidePool()
	target := pool[15]
	for i := 0; i < 8; i++ {
		p, err := v.SelectHSPath(pool, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Middle2 == nil {
			t.Fatal("应有 L3")
		}
		if p.Middle2.Fingerprint == target.Fingerprint || p.Middle.Fingerprint == target.Fingerprint || p.Guard.Fingerprint == target.Fingerprint {
			t.Fatal("L1/L2/L3 不得是目标")
		}
	}
}

func TestVanguardParamsFromConsensusDefaultsAndClamp(t *testing.T) {
	def := VanguardParamsFromConsensus(nil)
	if def.L2Count != 4 || def.L3Count != 8 {
		t.Fatalf("默认 L2/L3 = %d/%d", def.L2Count, def.L3Count)
	}
	if def.L2Min != defaultL2LifetimeMin || def.L2Max != defaultL2LifetimeMax {
		t.Fatal("默认 L2 寿命")
	}
	if def.L3Min != defaultL3LifetimeMin || def.L3Max != defaultL3LifetimeMax {
		t.Fatal("默认 L3 寿命")
	}
	clamped := VanguardParamsFromConsensus(map[string]int{
		"guard-hs-l2-number":       0,
		"guard-hs-l3-number":       100,
		"guard-hs-l2-lifetime-min": 0,
		"guard-hs-l2-lifetime-max": maxVanguardLifetimeSec + 10,
		"guard-hs-l3-lifetime-min": 10,
		"guard-hs-l3-lifetime-max": 5,
	})
	if clamped.L2Count != 1 {
		t.Fatalf("L2 number 下限 1, got %d", clamped.L2Count)
	}
	if clamped.L3Count != maxLayer3Count {
		t.Fatalf("L3 number 上限 %d, got %d", maxLayer3Count, clamped.L3Count)
	}
	if clamped.L2Min != time.Second {
		t.Fatalf("lifetime-min 下限 1s, got %s", clamped.L2Min)
	}
	if clamped.L2Max != time.Duration(maxVanguardLifetimeSec)*time.Second {
		t.Fatal("lifetime-max 应夹到 INT32_MAX 秒")
	}
	if clamped.L3Min != defaultL3LifetimeMin || clamped.L3Max != defaultL3LifetimeMax {
		t.Fatal("min>max 时应回退 L3 默认寿命")
	}
}

func TestVanguardSetApplyConsensusParamsResizes(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, L3Count: 8, MinLife: time.Hour, MaxLife: time.Hour, L3MinLife: time.Hour, L3MaxLife: time.Hour}, nil)
	pool := vgWidePool()
	if _, err := v.SelectHSPath(pool, pool[15], nil); err != nil {
		t.Fatal(err)
	}
	if len(v.Fingerprints()) != 4 || len(v.Layer3Fingerprints()) != 8 {
		t.Fatalf("初始 L2/L3 = %d/%d", len(v.Fingerprints()), len(v.Layer3Fingerprints()))
	}
	v.ApplyConsensusParams(VanguardParamsFromConsensus(map[string]int{
		"guard-hs-l2-number": 6,
		"guard-hs-l3-number": 4,
	}))
	if _, err := v.SelectHSPath(pool, pool[15], nil); err != nil {
		t.Fatal(err)
	}
	if len(v.Fingerprints()) != 6 {
		t.Fatalf("共识加大 L2 后应补到 6, got %v", v.Fingerprints())
	}
	if len(v.Layer3Fingerprints()) != 4 {
		t.Fatalf("共识缩小 L3 后应裁到 4, got %v", v.Layer3Fingerprints())
	}
}
