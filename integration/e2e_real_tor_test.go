//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/client"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/helpers"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
)

func keyPrefix(b []byte) []byte {
	if len(b) < 8 {
		return b
	}
	return b[:8]
}

func requireRealTor(t *testing.T) {
	t.Helper()
	if os.Getenv("TOR_INTEGRATION_TEST") != "1" {
		t.Skip("set TOR_INTEGRATION_TEST=1 to run real Tor Network tests")
	}
}

func advertisesCGO(r *directory.Relay) bool {
	return r != nil && r.SupportsSubprotoRequest() && r.Supports("Relay", 6) && r.RequestCongestionControl()
}

func pickRunningGuard(relays []*directory.Relay, preferCGO bool) *directory.Relay {
	var fallback *directory.Relay
	for _, r := range relays {
		if r == nil || !r.IsGuard() || !r.IsRunning() || r.ORPort <= 0 {
			continue
		}
		if fallback == nil {
			fallback = r
		}
		if preferCGO && advertisesCGO(r) {
			return r
		}
	}
	return fallback
}

func hopCGO(h *circuit.Hop) bool {
	return h != nil && h.CGO != nil
}

// TestRealConsensusSignatures 验收生产 FetchConsensus 强制校验权威签名。
// HTTP 仍可能 InsecureSkipVerify，但假共识无法凑齐 KnownAuthorities 的 PKCS#1 签名。
func TestRealConsensusSignatures(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dirClient := directory.NewClient(logger.NewDefault())
	relays, err := dirClient.FetchConsensus(ctx)
	if err != nil {
		t.Fatalf("FetchConsensus (with signature verification): %v", err)
	}
	if len(relays) < 1000 {
		t.Fatalf("verified consensus has too few relays: %d", len(relays))
	}
	t.Logf("consensus signatures verified, relays=%d", len(relays))
}

func TestRealGuardCreate2(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	relays, err := dirClient.FetchConsensus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guard := pickRunningGuard(relays, true)
	if guard == nil {
		t.Fatal("no guard in consensus")
	}
	if err := dirClient.FetchMicrodescriptorsFor(ctx, []*directory.Relay{guard}); err != nil {
		t.Fatal(err)
	}

	builder := circuit.NewBuilder(circuit.NewManager(), log)
	circ, err := builder.BuildFirstHop(ctx, guard, 90*time.Second)
	if err != nil {
		t.Fatalf("CREATE2: %v", err)
	}
	defer circ.Close()
	if circ.Length() < 1 {
		t.Fatalf("CREATE2 did not add guard hop")
	}
	hops := circ.GetHops()
	usedCGO := len(hops) > 0 && hopCGO(hops[0])
	if advertisesCGO(guard) && !usedCGO {
		t.Fatalf("guard %s 宣告 Relay=5/6+FlowCtrl=2 但 hop 仍是 tor1", guard.Nickname)
	}
	t.Logf("CREATE2 OK guard=%s fp=%s circuit=%d hops=%d handshake=%v ntorv3=%v flowctrl2=%v cgo_ad=%v cgo=%v",
		guard.Nickname, guard.GetFingerprintHex(), circ.ID, circ.Length(),
		circuit.HandshakeTypeFor(guard), guard.UseNtorV3(), guard.RequestCongestionControl(),
		advertisesCGO(guard), usedCGO)
}

// TestRealNtorV3 验收现行默认握手：HTYPE 0x0003、Ed25519 主身份、可选 FlowCtrl=2。
func TestRealNtorV3(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	relays, err := dirClient.FetchConsensus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guard := pickRunningGuard(relays, true)
	if guard == nil {
		t.Fatal("no guard in consensus")
	}
	if err := dirClient.FetchMicrodescriptorsFor(ctx, []*directory.Relay{guard}); err != nil {
		t.Fatal(err)
	}
	if !guard.UseNtorV3() {
		t.Fatalf("guard %s missing ntor-v3 keys or Relay=4", guard.Nickname)
	}
	if circuit.HandshakeTypeFor(guard) != circuit.HandshakeTypeNtorV3 {
		t.Fatalf("expected HandshakeTypeNtorV3, got %v", circuit.HandshakeTypeFor(guard))
	}

	builder := circuit.NewBuilder(circuit.NewManager(), log)
	circ, err := builder.BuildFirstHop(ctx, guard, 90*time.Second)
	if err != nil {
		t.Fatalf("ntor-v3 CREATE2: %v", err)
	}
	defer circ.Close()
	if circ.Length() < 1 {
		t.Fatal("ntor-v3 CREATE2 did not add guard hop")
	}
	hops := circ.GetHops()
	usedCGO := len(hops) > 0 && hopCGO(hops[0])
	if advertisesCGO(guard) && !usedCGO {
		t.Fatalf("guard %s 宣告 CGO 但 CREATE2 未建 CGO hop", guard.Nickname)
	}
	t.Logf("ntor-v3 OK guard=%s fp=%s pr_relay4=%v flowctrl2=%v sendme_inc=%d cgo_ad=%v cgo=%v",
		guard.Nickname, guard.GetFingerprintHex(),
		guard.Protocols.Supports("Relay", 4), guard.RequestCongestionControl(),
		circ.SendmeIncrement(), advertisesCGO(guard), usedCGO)
}

// TestExtend2Probe 区分 DESTROY reason=1 是 digest/crypto 失败还是 EXTEND2 语义被拒。
// RELAY_DROP 若被识别，Guard 会忽略且不拆路；若 digest 错误，Guard 会因无下一跳而 DESTROY 1。
func TestExtend2Probe(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	guardMgr, err := path.NewGuardManager(t.TempDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	selector := path.NewSelectorWithGuards(dirClient, guardMgr, log)
	if err := selector.UpdateConsensus(ctx); err != nil {
		t.Fatalf("UpdateConsensus: %v", err)
	}
	selected, err := selector.SelectPath(80)
	if err != nil {
		t.Fatalf("SelectPath: %v", err)
	}
	if err := dirClient.FetchMicrodescriptorsFor(ctx, []*directory.Relay{
		selected.Guard, selected.Middle, selected.Exit,
	}); err != nil {
		t.Fatalf("FetchMicrodescriptorsFor: %v", err)
	}
	if !selected.Middle.HasExtendKeys() {
		t.Fatalf("middle %s missing extend keys after microdesc fetch", selected.Middle.Nickname)
	}

	t.Logf("path guard=%s fp=%s ed=%x ntor=%x %s:%d",
		selected.Guard.Nickname, selected.Guard.GetFingerprintHex(), keyPrefix(selected.Guard.IdentityKey), keyPrefix(selected.Guard.NtorOnionKey),
		selected.Guard.Address, selected.Guard.ORPort)
	t.Logf("path middle=%s fp=%s ed=%x ntor=%x %s:%d",
		selected.Middle.Nickname, selected.Middle.GetFingerprintHex(), keyPrefix(selected.Middle.IdentityKey), keyPrefix(selected.Middle.NtorOnionKey),
		selected.Middle.Address, selected.Middle.ORPort)

	if selected.Guard.GetFingerprintHex() == selected.Middle.GetFingerprintHex() {
		t.Fatal("path selected the same relay as guard and middle")
	}

	builder := circuit.NewBuilder(circuit.NewManager(), log)
	circ, err := builder.BuildFirstHop(ctx, selected.Guard, 90*time.Second)
	if err != nil {
		t.Fatalf("CREATE2: %v", err)
	}
	defer circ.Close()

	drop, err := cell.NewRelayCell(0, cell.RelayDrop, []byte("gotor-drop-probe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := circ.SendRelayCell(drop); err != nil {
		t.Fatalf("send RELAY_DROP: %v", err)
	}

	select {
	case <-time.After(2 * time.Second):
		t.Log("RELAY_DROP did not DESTROY circuit in 2s → Guard recognized the cell (digest/AES likely OK)")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if circ.GetState() == circuit.StateFailed {
		t.Fatal("RELAY_DROP caused DESTROY: digest/recognized/AES-CTR 与 Guard 不一致")
	}

	ext := circuit.NewExtension(circ, log)
	ext.SetTargetRelay(selected.Middle)
	middleAddr := fmt.Sprintf("%s:%d", selected.Middle.Address, selected.Middle.ORPort)
	err = ext.ExtendCircuit(ctx, middleAddr, circuit.HandshakeTypeNTor)
	if err == nil {
		t.Logf("EXTEND2 OK hops=%d", circ.Length())
		return
	}
	t.Fatalf("EXTEND2 failed after recognized RELAY_DROP: %v", err)
}

func TestRealThreeHopCircuit(t *testing.T) {
	requireRealTor(t)
	circ, p := buildLiveCircuit(t)
	defer circ.Close()
	if circ.GetState() != circuit.StateOpen {
		t.Fatalf("circuit state %s", circ.GetState())
	}
	if circ.Length() != 3 {
		t.Fatalf("expected 3 hops, got %d", circ.Length())
	}
	hops := circ.GetHops()
	cgoFlags := make([]bool, len(hops))
	for i, h := range hops {
		cgoFlags[i] = hopCGO(h)
	}
	t.Logf("3-hop READY\n  Guard  %s %s cgo_ad=%v hop_cgo=%v\n  Middle %s %s cgo_ad=%v hop_cgo=%v\n  Exit   %s %s cgo_ad=%v hop_cgo=%v",
		p.Guard.Nickname, p.Guard.GetFingerprintHex(), advertisesCGO(p.Guard), cgoFlags[0],
		p.Middle.Nickname, p.Middle.GetFingerprintHex(), advertisesCGO(p.Middle), cgoFlags[1],
		p.Exit.Nickname, p.Exit.GetFingerprintHex(), advertisesCGO(p.Exit), cgoFlags[2])
}

func TestRealCheckTorProject(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	tor, err := client.ConnectWithContext(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer tor.Close()
	if err := tor.WaitUntilReady(3 * time.Minute); err != nil {
		t.Fatalf("WaitUntilReady: %v", err)
	}

	httpClient, err := helpers.NewHTTPClient(tor, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient.Timeout = 90 * time.Second

	// Exit DNS / RESOLVEFAILED 是对端偶发，不是协议错误；最多试 3 次。
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := httpClient.Get("https://check.torproject.org/api/ip")
		if err != nil {
			lastErr = fmt.Errorf("attempt %d GET: %w", attempt, err)
			t.Logf("%v", lastErr)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("attempt %d read: %w", attempt, err)
			t.Logf("%v", lastErr)
			continue
		}
		t.Logf("attempt %d check.torproject.org/api/ip status=%d raw=%s", attempt, resp.StatusCode, body)
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("attempt %d HTTP %d", attempt, resp.StatusCode)
			continue
		}

		var out struct {
			IsTor bool   `json:"IsTor"`
			IP    string `json:"IP"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			lastErr = fmt.Errorf("attempt %d json: %w", attempt, err)
			t.Logf("%v", lastErr)
			continue
		}
		if !out.IsTor {
			lastErr = fmt.Errorf("attempt %d IsTor=false IP=%s", attempt, out.IP)
			t.Logf("%v", lastErr)
			continue
		}
		if out.IP == "" {
			lastErr = fmt.Errorf("attempt %d empty exit IP", attempt)
			continue
		}
		t.Logf("IsTor=true ExitIP=%s", out.IP)
		return
	}
	t.Fatalf("check.torproject.org failed after %d attempts: %v", maxAttempts, lastErr)
}

// TestRealFlowControlSoak 下载足够 DATA 以触发电路级 SENDME。
// 约 100 个 DATA cell（~50KB）就会发第一个 v1 SENDME；若仍发空 v0，现代 exit 会 DESTROY。
func TestRealFlowControlSoak(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	tor, err := client.ConnectWithContext(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer tor.Close()
	if err := tor.WaitUntilReady(3 * time.Minute); err != nil {
		t.Fatalf("WaitUntilReady: %v", err)
	}

	httpClient, err := helpers.NewHTTPClient(tor, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient.Timeout = 2 * time.Minute

	// spec.torproject.org 经部分 exit 只回极短页面；重复拉 torproject.org 直到超过 1MB，
	// 以覆盖 FlowCtrl=2 Vegas + 多次电路级 SENDME v1。
	const wantBytes = 1024 * 1024
	var total int64
	for i := 0; total < wantBytes && i < 80; i++ {
		u := fmt.Sprintf("https://www.torproject.org/?soak=%d", i)
		resp, err := httpClient.Get(u)
		if err != nil {
			t.Logf("GET %s: %v", u, err)
			continue
		}
		n, err := io.Copy(io.Discard, resp.Body)
		status := resp.StatusCode
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read after %d bytes (likely SENDME/DESTROY): %v", total, err)
		}
		if status != 200 {
			t.Logf("HTTP %d from %s (%d bytes)", status, u, n)
			continue
		}
		total += n
		t.Logf("downloaded %d bytes status=%d total=%d", n, status, total)
	}
	if total < wantBytes {
		t.Fatalf("only downloaded %d bytes, want >= %d (need enough DATA to exercise SENDME)", total, wantBytes)
	}
	t.Logf("soak OK bytes=%d (circuit survived authenticated SENDME + FlowCtrl=2 Vegas)", total)
}

// TestRealRelayResolve 在 3-hop 上发 RELAY_RESOLVE，并把本机 resolver 指到不可达地址，
// 证明解析不依赖系统 DNS。StreamID=0 或二进制 PTR 会被真实 exit 丢掉。
func TestRealRelayResolve(t *testing.T) {
	requireRealTor(t)

	orig := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("本机 DNS 禁止使用: %s %s", network, address)
		},
	}
	t.Cleanup(func() { net.DefaultResolver = orig })

	circ, p := buildLiveCircuit(t)
	defer circ.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	result, err := circ.ResolveHostname(ctx, "www.torproject.org")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if len(result.Addresses) == 0 {
		t.Fatal("RELAY_RESOLVED 没有 IP")
	}
	t.Logf("RESOLVE www.torproject.org via exit %s -> %v ttl=%d type=0x%02X",
		p.Exit.Nickname, result.Addresses, result.TTL, result.Type)

	ptrCtx, ptrCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer ptrCancel()
	ptr, ptrErr := circ.ResolveIP(ptrCtx, result.Addresses[0])
	if ptrCtx.Err() != nil {
		t.Fatalf("PTR 超时（载荷/StreamID 很可能仍错）: %v", ptrErr)
	}
	if ptrErr != nil {
		t.Logf("PTR %s: %v（exit 可不答 PTR，但必须回 RESOLVED/END）", result.Addresses[0], ptrErr)
	} else {
		t.Logf("PTR %s -> %s ttl=%d", result.Addresses[0], ptr.Hostname, ptr.TTL)
	}

	failCtx, failCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer failCancel()
	_, err = circ.ResolveHostname(failCtx, "this-name-must-not-exist.invalid")
	if err == nil {
		t.Fatal(".invalid 主机名不应解析成功")
	}
	t.Logf("expected failure for .invalid: %v", err)
}

// TestRealConflux 验收两条 3-hop LINK 成功，且 SOCKS 拉到 IsTor=true。
// 缺握手时不得把单电路当成功。
func TestRealConflux(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	tor, err := client.ConnectWithContext(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer tor.Close()
	if err := tor.WaitUntilReady(4 * time.Minute); err != nil {
		t.Fatalf("WaitUntilReady: %v", err)
	}

	circ, err := tor.GetCircuit(ctx)
	if err != nil {
		t.Fatalf("GetCircuit: %v", err)
	}
	defer tor.ReturnCircuit(circ)

	if !circ.ConfluxLinked() {
		t.Fatalf("单电路不得标成 Conflux：ConfluxLinked=false info=%+v", circ.ConfluxInfo())
	}
	info := circ.ConfluxInfo()
	if len(info.Legs) != 2 {
		t.Fatalf("want 2 legs, got %+v", info)
	}
	a, b := info.Legs[0], info.Legs[1]
	if a.GuardFP == "" || b.GuardFP == "" || a.GuardFP == b.GuardFP {
		t.Fatalf("legs must use distinct guards: %+v", info)
	}
	if a.MiddleFP == "" || b.MiddleFP == "" || a.MiddleFP == b.MiddleFP {
		t.Fatalf("legs must use distinct middles: %+v", info)
	}
	if a.ExitFP == "" || a.ExitFP != b.ExitFP {
		t.Fatalf("legs must share one exit: %+v", info)
	}
	t.Logf("Conflux LINKED\n  leg0 circ=%d guard=%s middle=%s exit=%s rtt=%s\n  leg1 circ=%d guard=%s middle=%s exit=%s rtt=%s",
		a.CircuitID, a.GuardFP, a.MiddleFP, a.ExitFP, a.RTT,
		b.CircuitID, b.GuardFP, b.MiddleFP, b.ExitFP, b.RTT)

	httpClient, err := helpers.NewHTTPClient(tor, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient.Timeout = 90 * time.Second

	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := httpClient.Get("https://check.torproject.org/api/ip")
		if err != nil {
			lastErr = fmt.Errorf("attempt %d GET: %w", attempt, err)
			t.Logf("%v", lastErr)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("attempt %d read: %w", attempt, err)
			t.Logf("%v", lastErr)
			continue
		}
		t.Logf("attempt %d check.torproject.org/api/ip status=%d raw=%s", attempt, resp.StatusCode, body)
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("attempt %d HTTP %d", attempt, resp.StatusCode)
			continue
		}
		var out struct {
			IsTor bool   `json:"IsTor"`
			IP    string `json:"IP"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			lastErr = fmt.Errorf("attempt %d json: %w", attempt, err)
			continue
		}
		if !out.IsTor || out.IP == "" {
			lastErr = fmt.Errorf("attempt %d IsTor=%v IP=%s", attempt, out.IsTor, out.IP)
			continue
		}
		t.Logf("Conflux SOCKS IsTor=true ExitIP=%s", out.IP)
		return
	}
	t.Fatalf("check.torproject.org failed after %d attempts: %v", maxAttempts, lastErr)
}

func buildLiveCircuit(t *testing.T) (*circuit.Circuit, *path.Path) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	guardMgr, err := path.NewGuardManager(t.TempDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	selector := path.NewSelectorWithGuards(dirClient, guardMgr, log)
	if err := selector.UpdateConsensus(ctx); err != nil {
		t.Fatalf("UpdateConsensus: %v", err)
	}
	selected, err := selector.SelectPath(80)
	if err != nil {
		t.Fatalf("SelectPath: %v", err)
	}
	if err := dirClient.FetchMicrodescriptorsFor(ctx, []*directory.Relay{
		selected.Guard, selected.Middle, selected.Exit,
	}); err != nil {
		t.Fatalf("FetchMicrodescriptorsFor: %v", err)
	}

	builder := circuit.NewBuilder(circuit.NewManager(), log)
	circ, err := builder.BuildCircuit(ctx, selected, 90*time.Second)
	if err != nil {
		t.Fatalf("BuildCircuit: %v", err)
	}
	return circ, selected
}
