package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/config"
)

func TestNewDoSGuardFromConfigAutoIsOff(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.DoSCircuitCreationEnabled != config.DoSEnabledAuto {
		t.Fatalf("default Enabled = %d, want auto", cfg.DoSCircuitCreationEnabled)
	}
	g := NewDoSGuardFromConfig(cfg)
	if g == nil {
		t.Fatal("auto 也应构造守卫以便后续跟共识")
	}
	if g.circOn || g.connOn || g.streamOn {
		t.Fatal("auto 且无共识时不得启用 DoS 子系统")
	}
	g.ApplyConsensus(nil)
	if g.circOn || g.connOn || g.streamOn {
		t.Fatal("无共识参数仍应保持关闭")
	}
}

func TestNewDoSGuardFromConfigExplicitOn(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DoSCircuitCreationEnabled = config.DoSEnabledOn
	g := NewDoSGuardFromConfig(cfg)
	if g == nil || !g.circOn {
		t.Fatal("显式 1 应启用电路创建防御")
	}
}

func TestDoSGuardPerIPConcurrentConnections(t *testing.T) {
	g := NewDoSGuard(DoSConfig{
		ConnEnabled:   true,
		MaxConcurrent: 2,
	})
	if err := g.OnConnect("198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := g.OnConnect("198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := g.OnConnect("198.51.100.1"); err == nil {
		t.Fatal("第三路同 IP 应被拒")
	}
	if err := g.OnConnect("198.51.100.2"); err != nil {
		t.Fatal("其它 IP 不受影响")
	}
	g.OnDisconnect("198.51.100.1")
	if err := g.OnConnect("198.51.100.1"); err != nil {
		t.Fatal("释放后应再允许")
	}
}

func TestDoSGuardCreate2MinConnections(t *testing.T) {
	g := NewDoSGuard(DoSConfig{
		CircuitEnabled: true,
		MinConnections: 2,
		Rate:           1,
		Burst:          1,
		Defense:        time.Hour,
	})
	_ = g.OnConnect("198.51.100.8")
	for i := 0; i < 5; i++ {
		if err := g.AllowCreate2("198.51.100.8"); err != nil {
			t.Fatalf("未达 MinConnections 时第 %d 次应放行: %v", i+1, err)
		}
	}
}

func TestDoSGuardCreate2TokenBucketAndDefense(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	g := NewDoSGuard(DoSConfig{
		CircuitEnabled: true,
		MinConnections: 1,
		Rate:           1,
		Burst:          2,
		Defense:        time.Hour,
	})
	g.nowFn = func() time.Time { return now }
	_ = g.OnConnect("198.51.100.9")
	if err := g.AllowCreate2("198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	if err := g.AllowCreate2("198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	if err := g.AllowCreate2("198.51.100.9"); err == nil {
		t.Fatal("桶空应拒绝并进入防御窗")
	}
	now = now.Add(30 * time.Minute)
	if err := g.AllowCreate2("198.51.100.9"); err == nil {
		t.Fatal("防御窗内应继续拒绝")
	}
	now = now.Add(40 * time.Minute)
	if err := g.AllowCreate2("198.51.100.9"); err != nil {
		t.Fatalf("防御窗结束后应按时间补令牌再允许: %v", err)
	}
}

func TestDoSGuardConnLimitUnchangedSemantics(t *testing.T) {
	// 文档约束：DoS 不得改写 ConnLimit。守卫关闭时 OnConnect 只计数、不拒绝。
	g := NewDoSGuard(DoSConfig{ConnEnabled: false, MaxConcurrent: 1})
	for i := 0; i < 5; i++ {
		if err := g.OnConnect("198.51.100.3"); err != nil {
			t.Fatalf("连接防御关闭时不得因 MaxConcurrent 拒绝: %v", err)
		}
	}
}

func TestDoSRefuseSingleHopFlag(t *testing.T) {
	off := NewDoSGuard(DoSConfig{})
	if off.RefuseSingleHop() {
		t.Fatal("默认应关")
	}
	on := NewDoSGuard(DoSConfig{RefuseSingleHop: true})
	if !on.RefuseSingleHop() {
		t.Fatal("开关应为真")
	}
	cfg := config.DefaultConfig()
	cfg.DoSRefuseSingleHopClient = true
	g := NewDoSGuardFromConfig(cfg)
	if g == nil || !g.RefuseSingleHop() {
		t.Fatal("仅 RefuseSingleHop 也应构造守卫")
	}
}

func TestHandleCreate2DoSWritesDestroy(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	h := NewCircuitHandler(keys, nil)
	g := NewDoSGuard(DoSConfig{
		CircuitEnabled: true,
		MinConnections: 1,
		Rate:           1,
		Burst:          1,
		Defense:        time.Hour,
	})
	_ = g.OnConnect("192.168.1.100")
	if err := g.AllowCreate2("192.168.1.100"); err != nil {
		t.Fatal(err)
	}
	h.SetDoS(g)
	mock := newTestMockConn()
	if err := h.handleCreate2(mock, createMockCreate2Cell(1, keys)); err != nil {
		t.Fatal(err)
	}
	if h.GetCircuitCount() != 0 {
		t.Fatal("DoS 拒绝后不得留下电路")
	}
	if len(mock.writtenData) == 0 {
		t.Fatal("应写出 DESTROY")
	}
}

func TestFailedExtend2DoesNotMarkDidExtend(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	h := NewCircuitHandler(keys, nil)
	circ := &ServerCircuit{CircuitID: 3}
	h.mu.Lock()
	h.circuits[3] = circ
	h.mu.Unlock()
	rc, err := cell.NewRelayCell(0, cell.RelayExtend2, []byte{0xff})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.extender.HandleExtend2(context.Background(), 3, rc, nil); err == nil {
		t.Fatal("截断 EXTEND2 应失败")
	}
	circ.mu.RLock()
	marked := circ.didExtend
	circ.mu.RUnlock()
	if marked {
		t.Fatal("失败的 EXTEND2 不得置 didExtend，否则可绕过单跳拒绝")
	}
}

func TestRefuseSingleHopIfNeeded(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	h := NewCircuitHandler(keys, nil)
	h.SetDoS(NewDoSGuard(DoSConfig{RefuseSingleHop: true}))
	circ := &ServerCircuit{CircuitID: 7}
	if err := h.forwarder.refuseSingleHopIfNeeded(circ, nil); err == nil {
		t.Fatal("未 EXTEND 应拒绝")
	}
	circ.didExtend = true
	if err := h.forwarder.refuseSingleHopIfNeeded(circ, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRefuseSingleHopAllowsAuthenticatedRelay(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	h := NewCircuitHandler(keys, nil)
	h.SetDoS(NewDoSGuard(DoSConfig{RefuseSingleHop: true}))
	circ := &ServerCircuit{CircuitID: 8, linkAuthed: true}
	if err := h.forwarder.refuseSingleHopIfNeeded(circ, nil); err != nil {
		t.Fatal("已 AUTHENTICATE 的中继单跳应放行")
	}
}

func TestClientIPString(t *testing.T) {
	if got := clientIPString("192.0.2.1:9001"); got != "192.0.2.1" {
		t.Fatalf("got %q", got)
	}
	if got := clientIPString("[2001:db8::1]:9001"); got != "2001:db8::1" {
		t.Fatalf("got %q", got)
	}
}

func TestDoSGuardApplyConsensusAutoAndExplicit(t *testing.T) {
	cfg := config.DefaultConfig()
	g := NewDoSGuardFromConfig(cfg)
	g.ApplyConsensus(map[string]int{
		"DoSCircuitCreationEnabled": 1,
		"DoSConnectionEnabled":      1,
		"DoSStreamCreationEnabled":  1,
	})
	if !g.circOn || !g.connOn || !g.streamOn {
		t.Fatal("auto 应跟共识打开")
	}
	g.ApplyConsensus(map[string]int{
		"DoSCircuitCreationEnabled": 0,
		"DoSConnectionEnabled":      0,
		"DoSStreamCreationEnabled":  0,
	})
	if g.circOn || g.connOn || g.streamOn {
		t.Fatal("共识改回 0 时 auto 应关闭")
	}

	cfg.DoSCircuitCreationEnabled = config.DoSEnabledOn
	cfg.DoSConnectionEnabled = config.DoSEnabledOff
	cfg.DoSStreamCreationEnabled = config.DoSEnabledOff
	g = NewDoSGuardFromConfig(cfg)
	g.ApplyConsensus(map[string]int{
		"DoSCircuitCreationEnabled": 0,
		"DoSConnectionEnabled":      1,
		"DoSStreamCreationEnabled":  1,
	})
	if !g.circOn {
		t.Fatal("显式 1 不得被共识 0 关掉")
	}
	if g.connOn || g.streamOn {
		t.Fatal("显式 0 不得被共识 1 打开")
	}
}

func TestDoSGuardConnectRateBurstAndDefense(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	cfg := config.DefaultConfig()
	cfg.DoSConnectionEnabled = config.DoSEnabledOn
	g := NewDoSGuardFromConfig(cfg)
	g.nowFn = func() time.Time { return now }
	g.ApplyConsensus(map[string]int{
		"DoSConnectionConnectRate":              1,
		"DoSConnectionConnectBurst":             1,
		"DoSConnectionConnectDefenseTimePeriod": 3600,
	})
	if err := g.OnConnect("198.51.100.40"); err != nil {
		t.Fatal(err)
	}
	if err := g.OnConnect("198.51.100.40"); !errors.Is(err, errDoSConnectRate) {
		t.Fatalf("桶空应拒绝连接速率: %v", err)
	}
	now = now.Add(30 * time.Minute)
	if err := g.OnConnect("198.51.100.40"); !errors.Is(err, errDoSConnectRate) {
		t.Fatal("防御窗内应继续拒绝")
	}
	now = now.Add(40 * time.Minute)
	if err := g.OnConnect("198.51.100.40"); err != nil {
		t.Fatalf("防御窗结束后应允许: %v", err)
	}
}

func TestDoSGuardConnectRateTorrcOverridesConsensus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DoSConnectionEnabled = config.DoSEnabledOn
	cfg.DoSConnectionConnectRate = 2
	cfg.DoSConnectionConnectBurst = 2
	cfg.DoSConnectionConnectDefenseTime = time.Hour
	g := NewDoSGuardFromConfig(cfg)
	g.ApplyConsensus(map[string]int{
		"DoSConnectionConnectRate":  1,
		"DoSConnectionConnectBurst": 1,
	})
	if err := g.OnConnect("198.51.100.41"); err != nil {
		t.Fatal(err)
	}
	if err := g.OnConnect("198.51.100.41"); err != nil {
		t.Fatalf("torrc burst=2 应允许第二次: %v", err)
	}
	if err := g.OnConnect("198.51.100.41"); !errors.Is(err, errDoSConnectRate) {
		t.Fatalf("第三次应被速率桶拒绝: %v", err)
	}
}

func TestDoSGuardConnectRateDoesNotChangeConnLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	g := NewDoSGuardFromConfig(cfg)
	g.ApplyConsensus(map[string]int{
		"DoSConnectionConnectRate":  1,
		"DoSConnectionConnectBurst": 1,
	})
	for i := 0; i < 5; i++ {
		if err := g.OnConnect("198.51.100.42"); err != nil {
			t.Fatalf("auto 关闭时连接速率不得拒绝: %v", err)
		}
	}
}

func TestDoSGuardStreamCreationTokenBucket(t *testing.T) {
	now := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)
	g := NewDoSGuard(DoSConfig{
		StreamEnabled: true,
		StreamRate:    1,
		StreamBurst:   1,
		StreamDefense: dosStreamDefenseRefuse,
	})
	g.nowFn = func() time.Time { return now }
	if err := g.AllowBeginOrResolve(7); err != nil {
		t.Fatal(err)
	}
	if err := g.AllowBeginOrResolve(7); !errors.Is(err, errDoSStreamRefuse) {
		t.Fatalf("同电路桶空应拒绝流: %v", err)
	}
	if err := g.AllowBeginOrResolve(8); err != nil {
		t.Fatal("其它电路有独立桶")
	}
	now = now.Add(time.Second)
	if err := g.AllowBeginOrResolve(7); err != nil {
		t.Fatalf("补令牌后应允许: %v", err)
	}
}

func TestDoSGuardStreamCreationDefenseTypes(t *testing.T) {
	closeG := NewDoSGuard(DoSConfig{
		StreamEnabled: true,
		StreamRate:    1,
		StreamBurst:   1,
		StreamDefense: dosStreamDefenseClose,
	})
	_ = closeG.AllowBeginOrResolve(3)
	if err := closeG.AllowBeginOrResolve(3); !errors.Is(err, errDoSStreamClose) {
		t.Fatalf("type 3 应拆路: %v", err)
	}

	none := NewDoSGuard(DoSConfig{
		StreamEnabled: true,
		StreamRate:    1,
		StreamBurst:   1,
		StreamDefense: dosStreamDefenseNone,
	})
	_ = none.AllowBeginOrResolve(3)
	if err := none.AllowBeginOrResolve(3); err != nil {
		t.Fatalf("type 1 桶空仍应放行: %v", err)
	}
}

func TestDoSGuardStreamCreationTorrcOverridesConsensus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DoSStreamCreationEnabled = config.DoSEnabledOn
	cfg.DoSStreamCreationRate = 2
	cfg.DoSStreamCreationBurst = 2
	cfg.DoSStreamCreationDefenseType = dosStreamDefenseRefuse
	g := NewDoSGuardFromConfig(cfg)
	g.ApplyConsensus(map[string]int{
		"DoSStreamCreationRate":  1,
		"DoSStreamCreationBurst": 1,
	})
	if err := g.AllowBeginOrResolve(9); err != nil {
		t.Fatal(err)
	}
	if err := g.AllowBeginOrResolve(9); err != nil {
		t.Fatalf("torrc burst=2 应允许第二次: %v", err)
	}
	if err := g.AllowBeginOrResolve(9); !errors.Is(err, errDoSStreamRefuse) {
		t.Fatalf("第三次应拒绝: %v", err)
	}
}

func TestApplyStreamDoSClosesCircuit(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	h := NewCircuitHandler(keys, nil)
	h.SetDoS(NewDoSGuard(DoSConfig{
		StreamEnabled: true,
		StreamRate:    1,
		StreamBurst:   1,
		StreamDefense: dosStreamDefenseClose,
	}))
	circ := &ServerCircuit{CircuitID: 7}
	h.mu.Lock()
	h.circuits[7] = circ
	h.mu.Unlock()
	if err := h.forwarder.applyStreamDoS(circ, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := h.forwarder.applyStreamDoS(circ, nil, 2); !errors.Is(err, errDoSStreamClose) {
		t.Fatalf("type 3 应得 DESTROY: %v", err)
	}
	if h.GetCircuitCount() != 0 {
		t.Fatal("DefenseType 3 应拆掉电路")
	}
}

func TestApplyStreamDoSRefuseKeepsCircuit(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	h := NewCircuitHandler(keys, nil)
	h.SetDoS(NewDoSGuard(DoSConfig{
		StreamEnabled: true,
		StreamRate:    1,
		StreamBurst:   1,
		StreamDefense: dosStreamDefenseRefuse,
	}))
	circ := &ServerCircuit{CircuitID: 11}
	h.mu.Lock()
	h.circuits[11] = circ
	h.mu.Unlock()
	if err := h.forwarder.applyStreamDoS(circ, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := h.forwarder.applyStreamDoS(circ, nil, 2); !errors.Is(err, errDoSStreamRefuse) {
		t.Fatalf("type 2 应得 RELAY_END: %v", err)
	}
	if h.GetCircuitCount() != 1 {
		t.Fatal("拒绝流不得拆路")
	}
}
