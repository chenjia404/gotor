package path

import (
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
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: 2 * time.Hour}, nil)
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
	v := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4, MinLife: 24 * time.Hour, MaxLife: 24 * time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	first := v.Fingerprints()
	if len(first) != 4 {
		t.Fatalf("want 4, got %v", first)
	}
	again := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4}, nil)
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
	v := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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
	again := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4}, nil)
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
	v := NewVanguardSet(VanguardConfig{StatePath: state, AvoidDisk: true, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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
	v := NewVanguardSet(VanguardConfig{StatePath: state, Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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

func TestVanguardSetKeepsL2WhenTargetMatches(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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

func TestVanguardSetEvictsPersistL1FromL2(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	l2 := append([]string{}, v.Fingerprints()...)
	if len(l2) != 4 {
		t.Fatalf("%v", l2)
	}
	promoted := l2[0]
	p, err := v.SelectHSPath(pool, pool[6], []string{promoted})
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Fingerprint != promoted {
		t.Fatalf("升为 L1 后应使用持久入口，got %s", p.Guard.Nickname)
	}
	after := v.Fingerprints()
	if containsFP(after, promoted) {
		t.Fatal("已升为持久 L1 的节点不得留在 L2")
	}
	if len(after) != 4 {
		t.Fatalf("踢出后应补满 4，got %v", after)
	}
}

func TestVanguardSetRejectsL1SameFamilyAsTarget(t *testing.T) {
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
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
