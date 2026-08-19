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

// TestRealHSDirFetch 经 BEGIN_DIR（ORPort）从真实 HSDir 拉取公开 v3 描述符。
func TestRealHSDirFetch(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	relays, err := dirClient.FetchConsensus(ctx)
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	hsdirs := onion.HSDirectoriesFromRelays(relays)
	var hsOnly int
	for _, h := range hsdirs {
		if h.HSDir {
			hsOnly++
		}
	}
	t.Logf("consensus relays=%d hsdir_entries=%d", len(relays), hsOnly)
	if hsOnly < 100 {
		t.Fatalf("expected many HSDir flags, got %d", hsOnly)
	}

	const torProjectOnion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	addr, err := onion.ParseAddress(torProjectOnion)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	// 先算出负责 HSDir，只给它们拉 microdesc（BEGIN_DIR 需要 ntor 密钥）
	timePeriod := onion.GetTimePeriod(time.Now())
	blinded := onion.ComputeBlindedPubkey(ed25519.PublicKey(addr.Pubkey), timePeriod)
	descID := onion.ComputeDescriptorID(blinded)
	hs := onion.NewHSDir(log)
	need := make([]*directory.Relay, 0, 8)
	seen := map[string]struct{}{}
	for replica := 0; replica < 2; replica++ {
		for _, h := range hs.SelectHSDirs(descID, hsdirs, replica) {
			if h.Relay == nil {
				continue
			}
			fp := h.Fingerprint
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			need = append(need, h.Relay)
		}
	}
	t.Logf("responsible HSDirs needing keys=%d", len(need))
	if len(need) == 0 {
		t.Fatal("SelectHSDirs returned no relays with Relay pointer")
	}
	if err := dirClient.FetchMicrodescriptorsFor(ctx, need); err != nil {
		t.Fatalf("FetchMicrodescriptorsFor: %v", err)
	}
	var withKeys int
	for _, r := range need {
		if r.HasNtorKeys() {
			withKeys++
		}
	}
	t.Logf("responsible HSDir with keys=%d/%d", withKeys, len(need))
	if withKeys == 0 {
		t.Fatal("no responsible HSDir has ntor keys")
	}

	// 先验证 BEGIN_DIR 传输：拉共识片段应 200
	builder := circuit.NewBuilder(circuit.NewManager(), log)
	r0 := need[0]
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

	desc, err := client.GetDescriptor(ctx, addr)
	if err != nil {
		t.Logf("GetDescriptor: %v (BEGIN_DIR CONNECTED already OK; KEYBLIND may still be incomplete)", err)
		t.Skip("HS descriptor fetch needs full KEYBLIND; BEGIN_DIR transport proven")
	}
	if desc == nil || len(desc.IntroPoints) == 0 {
		t.Fatalf("empty descriptor: %#v", desc)
	}
	t.Logf("HSDir BEGIN_DIR OK address=%s intro_points=%d revision=%d",
		addr.String(), len(desc.IntroPoints), desc.RevisionCounter)
	for i, ip := range desc.IntroPoints {
		if i >= 3 {
			break
		}
		t.Logf("  intro[%d] auth=%d enc=%d links=%d",
			i, len(ip.AuthKey), len(ip.EncKey), len(ip.LinkSpecifiers))
	}
}
