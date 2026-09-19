package onion

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/path"
)

// PathMicrodescLoader 在握手前补齐路径上的 ntor / Ed25519。
// *directory.Client 已实现。拉不到就让建路失败，禁止用全零密钥顶上。
type PathMicrodescLoader interface {
	FetchMicrodescriptorsFor(ctx context.Context, relays []*directory.Relay) error
}

func ensurePathKeys(ctx context.Context, loader PathMicrodescLoader, p *path.Path) error {
	if loader == nil || p == nil {
		return nil
	}
	hops := make([]*directory.Relay, 0, 4)
	for _, r := range []*directory.Relay{p.Guard, p.Middle, p.Middle2, p.Exit} {
		if r != nil {
			hops = append(hops, r)
		}
	}
	if len(hops) == 0 {
		return nil
	}
	if err := loader.FetchMicrodescriptorsFor(ctx, hops); err != nil {
		return err
	}
	return nil
}

// selectOnionPath 已注入 VanguardSet 时必须走固定 L2（及默认 L3），失败则关闭（不得随机中间跳冒充）。
// 未配置 vanguards 时才退回随机 Guard/Middle。
func selectOnionPath(v *path.VanguardSet, gm *path.GuardManager, relays []*directory.Relay, target *directory.Relay) (*path.Path, error) {
	if target == nil {
		return nil, fmt.Errorf("onion path: nil target")
	}
	if v != nil {
		return v.SelectHSPath(relays, target, path.PersistL1Fingerprints(gm))
	}
	return randomAnonPath(relays, target)
}

func randomAnonPath(relays []*directory.Relay, exit *directory.Relay) (*path.Path, error) {
	guards := make([]*directory.Relay, 0, 32)
	middles := make([]*directory.Relay, 0, 64)
	for _, r := range relays {
		if r == nil || !r.IsRunning() || !r.IsValid() || !r.HasExtendKeys() {
			continue
		}
		if sameRelay(r, exit) {
			continue
		}
		if r.IsGuard() {
			guards = append(guards, r)
		}
		middles = append(middles, r)
	}
	if len(guards) == 0 || len(middles) == 0 {
		return nil, fmt.Errorf("insufficient path relays")
	}
	for try := 0; try < 48; try++ {
		g := guards[cryptoIntn(len(guards))]
		m := middles[cryptoIntn(len(middles))]
		if sameRelay(g, m) || sameRelay(m, exit) {
			continue
		}
		if g.InSameFamily(m) || g.InSameFamily(exit) || m.InSameFamily(exit) {
			continue
		}
		return &path.Path{Guard: g, Middle: m, Exit: exit}, nil
	}
	return &path.Path{Guard: guards[0], Middle: middles[0], Exit: exit}, nil
}

func cryptoIntn(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
