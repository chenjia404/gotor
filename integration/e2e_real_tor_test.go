//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	var guard *directory.Relay
	for _, r := range relays {
		if r.IsGuard() && r.IsRunning() && r.ORPort > 0 {
			guard = r
			break
		}
	}
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
	t.Logf("CREATE2 OK guard=%s fp=%s circuit=%d hops=%d", guard.Nickname, guard.GetFingerprintHex(), circ.ID, circ.Length())
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
	t.Logf("3-hop READY\n  Guard  %s %s\n  Middle %s %s\n  Exit   %s %s",
		p.Guard.Nickname, p.Guard.GetFingerprintHex(),
		p.Middle.Nickname, p.Middle.GetFingerprintHex(),
		p.Exit.Nickname, p.Exit.GetFingerprintHex())
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

	urls := []string{
		"https://spec.torproject.org/tor-spec.html",
		"https://spec.torproject.org/dir-spec.html",
		"https://www.torproject.org/",
		"https://spec.torproject.org/padding-spec.html",
	}
	const wantBytes = 256 * 1024
	var total int64
	for _, u := range urls {
		if total >= wantBytes {
			break
		}
		resp, err := httpClient.Get(u)
		if err != nil {
			t.Logf("GET %s: %v", u, err)
			continue
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Logf("read %s: %v", u, err)
			continue
		}
		total += n
		t.Logf("downloaded %d bytes from %s (total=%d)", n, u, total)
	}
	if total < wantBytes {
		t.Fatalf("only downloaded %d bytes, want >= %d (need enough DATA to exercise SENDME)", total, wantBytes)
	}
	t.Logf("soak OK bytes=%d (circuit survived authenticated SENDME)", total)
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
