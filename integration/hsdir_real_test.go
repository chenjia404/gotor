//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/onion"
	"github.com/opd-ai/go-tor/pkg/path"
	"golang.org/x/crypto/ed25519"
)

// TestRealHSDirFetch 经匿名 3-hop + BEGIN_DIR 从负责 HSDir 拉取公开 v3 描述符。
func TestRealHSDirFetch(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	relays, err := dirClient.FetchConsensus(ctx)
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	curSRV, prevSRV := dirClient.SharedRandomValues()
	t.Logf("consensus relays=%d srv_cur=%d srv_prev=%d valid_after=%v",
		len(relays), len(curSRV), len(prevSRV), dirClient.ConsensusValidAfter())
	if len(curSRV) != 32 && len(prevSRV) != 32 {
		t.Fatal("consensus missing shared-rand values")
	}

	hsdirs := onion.HSDirectoriesFromRelays(relays)
	var hsOnly []*directory.Relay
	for _, h := range hsdirs {
		if h.HSDir && h.Relay != nil {
			hsOnly = append(hsOnly, h.Relay)
		}
	}
	t.Logf("HSDir-flagged=%d", len(hsOnly))
	if len(hsOnly) < 100 {
		t.Fatalf("expected many HSDir flags, got %d", len(hsOnly))
	}

	t.Logf("fetching microdescriptors for %d HSDirs...", len(hsOnly))
	if err := dirClient.FetchMicrodescriptorsFor(ctx, hsOnly); err != nil {
		t.Fatalf("FetchMicrodescriptorsFor HSDirs: %v", err)
	}

	// Guard/Middle 密钥（匿名路径）
	var gm []*directory.Relay
	for _, r := range relays {
		if r == nil || !r.IsRunning() || r.HasExtendKeys() {
			continue
		}
		if r.IsGuard() || r.HasFlag("Fast") {
			gm = append(gm, r)
			if len(gm) >= 100 {
				break
			}
		}
	}
	if err := dirClient.FetchMicrodescriptorsFor(ctx, gm); err != nil {
		t.Logf("FetchMicrodescriptorsFor path relays: %v", err)
	}

	const torProjectOnion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	addr, err := onion.ParseAddress(torProjectOnion)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	timePeriod := onion.GetTimePeriod(time.Now())
	blinded := onion.ComputeBlindedPubkey(ed25519.PublicKey(addr.Pubkey), timePeriod)
	srv := onion.SelectSRVForFetch(time.Now(), timePeriod, curSRV, prevSRV)
	selected := onion.SelectResponsibleHSDirs(blinded, hsdirs, srv, timePeriod, 0, 0)
	t.Logf("period=%d blinded=%x... responsible=%d", timePeriod, blinded[:8], len(selected))
	if len(selected) == 0 {
		t.Fatal("SelectResponsibleHSDirs returned empty")
	}

	builder := circuit.NewBuilder(circuit.NewManager(), log)
	begindir := onion.NewBegindirFetcher(builder, log)
	begindir.SetRelays(relays)

	guard := pickWithKeys(relays, true)
	middle := pickWithKeys(relays, false)
	if guard == nil || middle == nil || selected[0].Relay == nil {
		t.Fatal("missing guard/middle/hsdir keys")
	}
	circ, err := builder.BuildCircuit(ctx, &path.Path{
		Guard:  guard,
		Middle: middle,
		Exit:   selected[0].Relay,
	}, 90*time.Second)
	if err != nil {
		t.Fatalf("BuildCircuit 3-hop: %v", err)
	}
	sid, err := circ.AllocateStreamID()
	if err != nil {
		circ.Close()
		t.Fatal(err)
	}
	if err := circ.OpenDirStream(ctx, sid); err != nil {
		circ.Close()
		t.Fatalf("OpenDirStream BEGIN_DIR: %v", err)
	}
	_ = circ.EndStream(sid, 6)
	circ.ReleaseStreamID(sid)
	circ.Close()
	t.Logf("anonymous BEGIN_DIR CONNECTED OK exit=%s guard=%s", selected[0].Relay.Nickname, guard.Nickname)

	client := onion.NewClient(log)
	client.UpdateHSDirs(hsdirs)
	client.SetBegindir(begindir)
	client.SetSharedRandom(curSRV, prevSRV)

	desc, err := client.GetDescriptor(ctx, addr)
	if err != nil {
		t.Fatalf("GetDescriptor: %v", err)
	}
	if desc == nil || len(desc.IntroPoints) == 0 {
		t.Fatalf("empty descriptor: %#v", desc)
	}
	t.Logf("HSDir fetch OK address=%s intro_points=%d revision=%d",
		addr.String(), len(desc.IntroPoints), desc.RevisionCounter)
	for i, ip := range desc.IntroPoints {
		if i >= 3 {
			break
		}
		t.Logf("  intro[%d] auth=%d enc=%d links=%d",
			i, len(ip.AuthKey), len(ip.EncKey), len(ip.LinkSpecifiers))
	}
}

func pickWithKeys(relays []*directory.Relay, guard bool) *directory.Relay {
	for _, r := range relays {
		if r == nil || !r.HasExtendKeys() || !r.IsRunning() {
			continue
		}
		if guard {
			if r.IsGuard() {
				return r
			}
			continue
		}
		if !r.IsGuard() {
			return r
		}
	}
	for _, r := range relays {
		if r != nil && r.HasExtendKeys() {
			return r
		}
	}
	return nil
}
