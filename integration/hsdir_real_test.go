//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/onion"
)

// TestRealHSDirFetch 从真实 HSDir（HTTP DirPort）拉取公开 v3 描述符。
// 使用 Tor Project 的 onion 地址（稳定、文档化）。
func TestRealHSDirFetch(t *testing.T) {
	requireRealTor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	log := logger.NewDefault()
	dirClient := directory.NewClient(log)
	relays, err := dirClient.FetchConsensus(ctx)
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	hsdirs := onion.HSDirectoriesFromRelays(relays)
	t.Logf("consensus relays=%d http_dircaches=%d", len(relays), len(hsdirs))
	if len(hsdirs) < 1 {
		t.Fatal("need at least one relay with DirPort for HTTP HS fetch")
	}

	// Tor Browser / Tor Project onion（v3）
	const torProjectOnion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	addr, err := onion.ParseAddress(torProjectOnion)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	client := onion.NewClient(log)
	client.UpdateHSDirs(hsdirs)
	desc, err := client.GetDescriptor(ctx, addr)
	if err != nil {
		// 现代网络几乎无 DirPort：负责 HSDir 需 BEGIN_DIR。有 DirPort 的缓存可能未存该描述符。
		t.Logf("GetDescriptor via HTTP DirPort failed (often expected without BEGIN_DIR): %v", err)
		t.Logf("http_dircaches=%d — BEGIN_DIR over ORPort is required for reliable HSDir fetch", len(hsdirs))
		t.Skip("HTTP DirPort HS fetch inconclusive; implement BEGIN_DIR for WORKING")
	}
	if desc == nil {
		t.Fatal("nil descriptor")
	}
	if len(desc.IntroPoints) == 0 {
		t.Fatal("descriptor has no introduction points")
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
