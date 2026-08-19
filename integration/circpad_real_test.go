//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
)

// TestRealCircpadNegotiate 在真实 3-hop 上对宣告 Padding=2 的 middle 发送 PADDING_NEGOTIATE。
func TestRealCircpadNegotiate(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dir := directory.NewClient(log)
	relays, err := dir.FetchConsensus(ctx)
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	pp := directory.GetPaddingParams(&directory.ConsensusMetadata{Params: dir.LastConsensusParams()})
	if pp != nil && pp.PaddingDisabled {
		t.Skip("circpad_padding_disabled in consensus")
	}

	var guards, middles, exits []*directory.Relay
	for _, r := range relays {
		if r == nil || !r.IsRunning() || !r.IsValid() {
			continue
		}
		if r.IsGuard() {
			guards = append(guards, r)
		}
		if r.HasFlag("Fast") && r.Protocols.Supports("Padding", 2) {
			middles = append(middles, r)
		}
		if r.HasFlag("Exit") && r.HasFlag("Fast") {
			exits = append(exits, r)
		}
	}
	t.Logf("candidates guards=%d padding2_middles=%d exits=%d", len(guards), len(middles), len(exits))
	if len(guards) == 0 || len(middles) < 2 || len(exits) == 0 {
		t.Skip("insufficient Padding=2 path candidates")
	}

	// 预取一批密钥
	sample := make([]*directory.Relay, 0, 40)
	sample = append(sample, guards[:min(10, len(guards))]...)
	sample = append(sample, middles[:min(20, len(middles))]...)
	sample = append(sample, exits[:min(10, len(exits))]...)
	_ = dir.FetchMicrodescriptorsFor(ctx, sample)

	mgr := circuit.NewManager()
	builder := circuit.NewBuilder(mgr, log)
	var circ *circuit.Circuit
	var lastErr error
	var usedMiddle string
	for attempt := 0; attempt < 12; attempt++ {
		g := guards[attempt%len(guards)]
		m := middles[attempt%len(middles)]
		e := exits[(attempt*3)%len(exits)]
		if sameFP(g, m) || sameFP(m, e) || sameFP(g, e) {
			continue
		}
		need := []*directory.Relay{}
		for _, r := range []*directory.Relay{g, m, e} {
			if !r.HasExtendKeys() {
				need = append(need, r)
			}
		}
		if len(need) > 0 {
			_ = dir.FetchMicrodescriptorsFor(ctx, need)
		}
		if !g.HasExtendKeys() || !m.HasExtendKeys() || !e.HasExtendKeys() {
			continue
		}
		p := &path.Path{Guard: g, Middle: m, Exit: e}
		circ, lastErr = builder.BuildCircuit(ctx, p, 90*time.Second)
		if lastErr == nil {
			usedMiddle = m.Nickname
			break
		}
		t.Logf("attempt %d failed: %v", attempt+1, lastErr)
	}
	if circ == nil {
		t.Fatalf("BuildCircuit: %v", lastErr)
	}
	t.Logf("circuit %d hops=%d middle=%s Padding=2", circ.ID, len(circ.GetHops()), usedMiddle)

	cfg := circuit.CircpadConfigFromParams(false, 0)
	if err := circ.StartHSSetupPadding(circuit.HSSetupRend, true, cfg); err != nil {
		t.Fatalf("StartHSSetupPadding: %v", err)
	}
	ctrl := circ.Circpad()
	if ctrl == nil || !ctrl.NegotiateSent() {
		t.Fatal("expected circpad negotiate sent")
	}
	t.Logf("PADDING_NEGOTIATE sent machine_ctr=%d state=%d", ctrl.MachineCtr(), ctrl.State())

	waitCtx, cancelWait := context.WithTimeout(ctx, 8*time.Second)
	defer cancelWait()
	gotNegotiated := false
	gotDrop := false
	for {
		rc, err := circ.ReceiveRelayCell(waitCtx)
		if err != nil {
			break
		}
		switch rc.Command {
		case 42:
			gotNegotiated = true
			if n, err := circuit.DecodeCircpadNegotiated(rc.Data); err == nil {
				t.Logf("PADDING_NEGOTIATED response=%d ctr=%d", n.Response, n.MachineCtr)
				_ = ctrl.OnNegotiated(n)
			}
		case 10:
			gotDrop = true
			ctrl.OnPaddingRecv()
		}
		if gotNegotiated {
			break
		}
	}
	t.Logf("negotiate_ack=%v drop=%v final_state=%d active=%v",
		gotNegotiated, gotDrop, ctrl.State(), ctrl.Active())
	if !ctrl.NegotiateSent() {
		t.Fatal("negotiate not marked sent")
	}
}

func sameFP(a, b *directory.Relay) bool {
	if a == nil || b == nil {
		return false
	}
	fa, fb := a.GetFingerprintHex(), b.GetFingerprintHex()
	return fa != "" && fa == fb
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
