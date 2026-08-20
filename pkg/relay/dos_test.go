package relay

import (
	"context"
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
	if g := NewDoSGuardFromConfig(cfg); g != nil {
		t.Fatal("auto 且无共识时不得启用 DoS 子系统")
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

func TestClientIPString(t *testing.T) {
	if got := clientIPString("192.0.2.1:9001"); got != "192.0.2.1" {
		t.Fatalf("got %q", got)
	}
	if got := clientIPString("[2001:db8::1]:9001"); got != "2001:db8::1" {
		t.Fatalf("got %q", got)
	}
}
