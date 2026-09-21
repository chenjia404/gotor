// Package onion — 经匿名电路的 BEGIN_DIR 目录拉取。
package onion

import (
	"context"
	"fmt"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
)

// BegindirFetcher 经 ORPort + RELAY_BEGIN_DIR 拉取目录 HTTP 资源。
// HS v3 描述符要求匿名电路（非单跳），否则 HSDir 回 503。
type BegindirFetcher struct {
	builder   *circuit.Builder
	logger    *logger.Logger
	relays    []*directory.Relay // 共识 relay（需含 Guard/Middle 密钥）
	vanguards *path.VanguardSet
	guards    *path.GuardManager
	keys      PathMicrodescLoader
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

// SetMicrodescLoader 在建路前拉取路径 hop 的 microdesc。未设置时仍拒绝零密钥。
func (f *BegindirFetcher) SetMicrodescLoader(l PathMicrodescLoader) {
	if f == nil {
		return
	}
	f.keys = l
}

// SetVanguards 注入 vanguards-lite，供 HSDir BEGIN_DIR 电路使用。
func (f *BegindirFetcher) SetVanguards(v *path.VanguardSet, gm *path.GuardManager) {
	if f == nil {
		return
	}
	f.vanguards = v
	f.guards = gm
}

// beginDirAttemptBudget 是单个 HSDir 建路的上限。
// 健康的四跳大约 2 秒；超时就换下一个目录，不再对同一个目录建第二次。
const beginDirAttemptBudget = 12 * time.Second

func beginDirBudget(ctx context.Context) time.Duration {
	budget := beginDirAttemptBudget
	if ctx == nil {
		return budget
	}
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl); remain < budget {
			budget = remain
		}
	}
	if budget < time.Second {
		return time.Second
	}
	return budget
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

	p, err := f.selectAnonPath(relay)
	if err != nil {
		return nil, err
	}

	var circ *circuit.Circuit
	var lastBuild error
	// 每个 HSDir 只建一次。第二次会把 12 秒预算再花掉，后面真正存着描述符的目录轮不到。
	if err := ensurePathKeys(ctx, f.keys, p); err != nil {
		return nil, fmt.Errorf("microdescriptors for BEGIN_DIR path: %w", err)
	}
	circ, lastBuild = f.builder.BuildCircuit(ctx, p, beginDirBudget(ctx))
	if circ == nil {
		if lastBuild == nil {
			lastBuild = fmt.Errorf("circuit build returned nil")
		}
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
		if err := ensurePathKeys(ctx, f.keys, p); err != nil {
			lastBuild = fmt.Errorf("microdescriptors for BEGIN_DIR path: %w", err)
			continue
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
	return selectOnionPath(f.vanguards, f.guards, f.relays, exit)
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
