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
// 父 context 剩余时间更短时跟着缩短，避免把即将到期的请求再拖 30 秒。
const beginDirAttemptBudget = 15 * time.Second

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
	// 单个 HSDir 最多建两次。预算跟父级 deadline 走，不再把不足 30 秒的剩余时间抬回 30 秒，
	// 否则一条慢电路会吃掉整个洋葱连接。
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			p, err = f.selectAnonPath(relay)
			if err != nil {
				return nil, err
			}
		}
		if err := ensurePathKeys(ctx, f.keys, p); err != nil {
			lastBuild = fmt.Errorf("microdescriptors for BEGIN_DIR path: %w", err)
			f.logger.Debug("3-hop microdescriptors failed, retrying",
				"attempt", attempt+1, "error", lastBuild)
			continue
		}
		circ, lastBuild = f.builder.BuildCircuit(ctx, p, beginDirBudget(ctx))
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
