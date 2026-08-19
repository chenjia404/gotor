package onion

import (
	"context"
	"fmt"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// BegindirFetcher 经 ORPort + RELAY_BEGIN_DIR 拉取目录 HTTP 资源。
type BegindirFetcher struct {
	builder *circuit.Builder
	logger  *logger.Logger
}

// NewBegindirFetcher 创建拉取器；builder 须已配置。
func NewBegindirFetcher(builder *circuit.Builder, log *logger.Logger) *BegindirFetcher {
	if log == nil {
		log = logger.NewDefault()
	}
	return &BegindirFetcher{builder: builder, logger: log.Component("begindir")}
}

// Fetch 对 relay 建 1-hop 电路，BEGIN_DIR 后 GET path，返回响应体。
func (f *BegindirFetcher) Fetch(ctx context.Context, relay *directory.Relay, path string) ([]byte, error) {
	if f == nil || f.builder == nil {
		return nil, fmt.Errorf("begindir fetcher not configured")
	}
	if relay == nil || !relay.HasNtorKeys() {
		return nil, fmt.Errorf("relay missing ntor keys for BEGIN_DIR")
	}
	if path == "" || path[0] != '/' {
		return nil, fmt.Errorf("path must start with /")
	}

	timeout := 60 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
		if timeout < 10*time.Second {
			timeout = 10 * time.Second
		}
	}
	circ, err := f.builder.BuildFirstHop(ctx, relay, timeout)
	if err != nil {
		return nil, fmt.Errorf("build 1-hop for BEGIN_DIR: %w", err)
	}
	defer circ.Close()

	host := fmt.Sprintf("%s:%d", relay.Address, relay.ORPort)
	body, err := circ.FetchHTTPViaBeginDir(ctx, host, path)
	if err != nil {
		return nil, fmt.Errorf("BEGIN_DIR HTTP GET %s: %w", path, err)
	}
	f.logger.Debug("BEGIN_DIR fetch OK",
		"relay", relay.Nickname, "path", path, "bytes", len(body))
	return body, nil
}
