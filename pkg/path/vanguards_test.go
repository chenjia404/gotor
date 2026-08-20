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
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	v := NewVanguardSet(VanguardConfig{Count: 4, MinLife: time.Hour, MaxLife: time.Hour}, nil)
	v.nowFn = func() time.Time { return now }
	pool := vgPool()
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	before := append([]string{}, v.Fingerprints()...)
	now = now.Add(2 * time.Hour)
	if _, err := v.SelectHSPath(pool, pool[6], nil); err != nil {
		t.Fatal(err)
	}
	after := v.Fingerprints()
	if len(after) != 4 {
		t.Fatalf("过期后应补满 4，got %v", after)
	}
	same := 0
	for _, fp := range before {
		if containsFP(after, fp) {
			same++
		}
	}
	if same == 4 {
		t.Fatal("全部过期后不应原样保留")
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
