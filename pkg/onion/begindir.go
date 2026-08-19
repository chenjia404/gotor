// Package onion — 经匿名电路的 BEGIN_DIR 目录拉取。
package onion

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
)

// BegindirFetcher 经 ORPort + RELAY_BEGIN_DIR 拉取目录 HTTP 资源。
// HS v3 描述符要求匿名电路（非单跳），否则 HSDir 回 503。
type BegindirFetcher struct {
	builder *circuit.Builder
	logger  *logger.Logger
	relays  []*directory.Relay // 共识 relay（需含 Guard/Middle 密钥）
}

// NewBegindirFetcher 创建拉取器；builder 须已配置。
func NewBegindirFetcher(builder *circuit.Builder, log *logger.Logger) *BegindirFetcher {
	if log == nil {
		log = logger.NewDefault()
	}
	return &BegindirFetcher{builder: builder, logger: log.Component("begindir")}
}

// SetRelays 注入共识节点，用于构造 Guard→Middle→HSDir 三跳。
func (f *BegindirFetcher) SetRelays(relays []*directory.Relay) {
	if f == nil {
		return
	}
	f.relays = relays
}

// Fetch 对 HSDir 建匿名 3-hop 电路（HSDir 为末跳），BEGIN_DIR 后 GET path。
func (f *BegindirFetcher) Fetch(ctx context.Context, relay *directory.Relay, httpPath string) ([]byte, error) {
	if f == nil || f.builder == nil {
		return nil, fmt.Errorf("begindir fetcher not configured")
	}
	if relay == nil || !relay.HasNtorKeys() {
		return nil, fmt.Errorf("relay missing ntor keys for BEGIN_DIR")
	}
	if httpPath == "" || httpPath[0] != '/' {
		return nil, fmt.Errorf("path must start with /")
	}

	timeout := 90 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
		if timeout < 30*time.Second {
			timeout = 30 * time.Second
		}
	}

	p, err := f.selectAnonPath(relay)
	if err != nil {
		return nil, err
	}

	var circ *circuit.Circuit
	var lastBuild error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			p, err = f.selectAnonPath(relay)
			if err != nil {
				return nil, err
			}
		}
		circ, lastBuild = f.builder.BuildCircuit(ctx, p, timeout)
		if lastBuild == nil {
			break
		}
		f.logger.Debug("3-hop build failed, retrying",
			"attempt", attempt+1, "error", lastBuild,
			"guard", p.Guard.Nickname, "middle", p.Middle.Nickname)
	}
	if circ == nil {
		return nil, fmt.Errorf("build 3-hop for BEGIN_DIR: %w", lastBuild)
	}
	defer circ.Close()

	host := fmt.Sprintf("%s:%d", relay.Address, relay.ORPort)
	body, err := circ.FetchHTTPViaBeginDir(ctx, host, httpPath)
	if err != nil {
		return nil, fmt.Errorf("BEGIN_DIR HTTP GET %s: %w", httpPath, err)
	}
	f.logger.Debug("BEGIN_DIR fetch OK",
		"hsdir", relay.Nickname,
		"guard", p.Guard.Nickname,
		"middle", p.Middle.Nickname,
		"path", httpPath,
		"bytes", len(body))
	return body, nil
}

// Post 经匿名 3-hop BEGIN_DIR 向 HSDir POST 描述符（/tor/hs/3/publish）。
func (f *BegindirFetcher) Post(ctx context.Context, relay *directory.Relay, httpPath string, body []byte) error {
	if f == nil || f.builder == nil {
		return fmt.Errorf("begindir fetcher not configured")
	}
	if relay == nil || !relay.HasNtorKeys() {
		return fmt.Errorf("relay missing ntor keys for BEGIN_DIR POST")
	}
	if httpPath == "" || httpPath[0] != '/' {
		return fmt.Errorf("path must start with /")
	}
	timeout := 90 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
		if timeout < 30*time.Second {
			timeout = 30 * time.Second
		}
	}
	p, err := f.selectAnonPath(relay)
	if err != nil {
		return err
	}
	var circ *circuit.Circuit
	var lastBuild error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			p, err = f.selectAnonPath(relay)
			if err != nil {
				return err
			}
		}
		circ, lastBuild = f.builder.BuildCircuit(ctx, p, timeout)
		if lastBuild == nil {
			break
		}
	}
	if circ == nil {
		return fmt.Errorf("build 3-hop for BEGIN_DIR POST: %w", lastBuild)
	}
	defer circ.Close()
	host := fmt.Sprintf("%s:%d", relay.Address, relay.ORPort)
	resp, err := circ.PostHTTPViaBeginDir(ctx, host, httpPath, body)
	if err != nil {
		return fmt.Errorf("BEGIN_DIR HTTP POST %s: %w", httpPath, err)
	}
	f.logger.Debug("BEGIN_DIR POST OK", "path", httpPath, "resp_bytes", len(resp))
	return nil
}

func (f *BegindirFetcher) selectAnonPath(exit *directory.Relay) (*path.Path, error) {
	if len(f.relays) == 0 {
		return nil, fmt.Errorf("begindir: no consensus relays for anonymous path")
	}
	guards := make([]*directory.Relay, 0, 32)
	middles := make([]*directory.Relay, 0, 64)
	for _, r := range f.relays {
		if r == nil || !r.IsRunning() || !r.IsValid() || !r.HasExtendKeys() {
			continue
		}
		if sameRelay(r, exit) {
			continue
		}
		if r.IsGuard() {
			guards = append(guards, r)
		}
		if !r.HasFlag("BadExit") {
			middles = append(middles, r)
		}
	}
	if len(guards) == 0 || len(middles) == 0 {
		return nil, fmt.Errorf("begindir: need Guard/Middle with keys (guards=%d middles=%d)",
			len(guards), len(middles))
	}

	var guard, middle *directory.Relay
	for attempt := 0; attempt < 64; attempt++ {
		g := guards[rand.Intn(len(guards))]
		m := middles[rand.Intn(len(middles))]
		if sameRelay(g, m) || sameRelay(g, exit) || sameRelay(m, exit) {
			continue
		}
		if g.InSameFamily(m) || g.InSameFamily(exit) || m.InSameFamily(exit) {
			continue
		}
		guard, middle = g, m
		break
	}
	if guard == nil || middle == nil {
		// 放宽：仅避开同一节点
		guard = guards[rand.Intn(len(guards))]
		for _, m := range middles {
			if !sameRelay(m, guard) && !sameRelay(m, exit) {
				middle = m
				break
			}
		}
	}
	if guard == nil || middle == nil {
		return nil, fmt.Errorf("begindir: could not pick distinct Guard/Middle")
	}
	return &path.Path{Guard: guard, Middle: middle, Exit: exit}, nil
}

func sameRelay(a, b *directory.Relay) bool {
	if a == nil || b == nil {
		return false
	}
	if a == b {
		return true
	}
	fa, fb := a.GetFingerprintHex(), b.GetFingerprintHex()
	return fa != "" && fa == fb
}
