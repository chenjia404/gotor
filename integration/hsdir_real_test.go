//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/onion"
	"golang.org/x/crypto/ed25519"
)

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// TestRealHSDirFetch 经 BEGIN_DIR 从真实负责 HSDir 拉取公开 v3 描述符。
func TestRealHSDirFetch(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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

	// 哈希环需要全部 HSDir 的 Ed25519 身份（microdesc id ed25519）
	t.Logf("fetching microdescriptors for %d HSDirs...", len(hsOnly))
	if err := dirClient.FetchMicrodescriptorsFor(ctx, hsOnly); err != nil {
		t.Logf("FetchMicrodescriptorsFor warning: %v", err)
	}
	var withID, withNtor int
	for _, r := range hsOnly {
		if len(r.IdentityKey) == 32 {
			withID++
		}
		if r.HasNtorKeys() {
			withNtor++
		}
	}
	t.Logf("HSDir with ed25519=%d ntor=%d / %d", withID, withNtor, len(hsOnly))
	if withID < 50 {
		t.Fatalf("too few HSDir identities: %d", withID)
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
	// 验证 BEGIN_DIR 传输
	r0 := selected[0].Relay
	circ, err := builder.BuildFirstHop(ctx, r0, 60*time.Second)
	if err != nil {
		t.Fatalf("BuildFirstHop: %v", err)
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
	t.Logf("BEGIN_DIR CONNECTED OK via %s (%s:%d)", r0.Nickname, r0.Address, r0.ORPort)

	begindir := onion.NewBegindirFetcher(builder, log)
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
	_ = itoa
}
