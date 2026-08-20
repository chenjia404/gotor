package directory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	cachedMicrodescConsensusName     = "cached-microdesc-consensus"
	cachedMicrodescConsensusPrevName = "cached-microdesc-consensus.prev"
	maxCachedConsensusBytes          = maxConsensusDownloadBytes
)

// EnableConsensusDiskCache 启用 CacheDirectory/cached-microdesc-consensus。
// 启动时不自动加载（由 FetchConsensus 在内存无缓存时尝试）。
func (c *Client) EnableConsensusDiskCache(cacheDir string) error {
	if c == nil {
		return fmt.Errorf("directory client not initialized")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cacheDir == "" {
		c.consensusDiskPath = ""
		return nil
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("create consensus cache dir: %w", err)
	}
	c.consensusDiskPath = filepath.Join(cacheDir, cachedMicrodescConsensusName)
	c.avoidDiskWrites = false
	return nil
}

// SetAvoidDiskWrites 禁止把共识/microdesc 写回磁盘。
func (c *Client) SetAvoidDiskWrites(v bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.avoidDiskWrites = v
	c.mu.Unlock()
}

func (c *Client) tryLoadConsensusDisk(ctx context.Context) ([]*Relay, error) {
	c.mu.RLock()
	path := c.consensusDiskPath
	c.mu.RUnlock()
	if path == "" {
		return nil, fmt.Errorf("consensus disk cache disabled")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- CacheDirectory 由操作者配置
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxCachedConsensusBytes {
		return nil, fmt.Errorf("cached consensus empty or too large")
	}
	relays, err := c.ingestConsensusDocument(ctx, string(data))
	if err != nil {
		c.logger.Info("cached-microdesc-consensus rejected", "error", err)
		return nil, err
	}
	c.logger.Info("loaded consensus from disk", "relays", len(relays), "path", path)
	return relays, nil
}

func (c *Client) persistConsensusDisk(doc string) {
	c.mu.RLock()
	path := c.consensusDiskPath
	avoid := c.avoidDiskWrites
	c.mu.RUnlock()
	if avoid || path == "" || strings.TrimSpace(doc) == "" {
		return
	}
	if len(doc) > maxCachedConsensusBytes {
		c.logger.Warn("refusing to write oversized cached-microdesc-consensus")
		return
	}
	// 换共识时保留上一份，供 DirCache 按 X-Or-Diff-From-Consensus 生成 limited-ed。
	if existing, err := os.ReadFile(path); err == nil && len(existing) > 0 && len(existing) <= maxCachedConsensusBytes {
		oldFrom := consensusDiffFromDigest(string(existing))
		newFrom := consensusDiffFromDigest(doc)
		if hexDigestEqual(oldFrom, newFrom) {
			return
		}
		prevPath := filepath.Join(filepath.Dir(path), cachedMicrodescConsensusPrevName)
		if err := writeFileAtomic(prevPath, existing, 0o600); err != nil {
			c.logger.Warn("failed to persist previous consensus for consdiff", "error", err)
		}
	}
	if err := writeFileAtomic(path, []byte(doc), 0o600); err != nil {
		c.logger.Warn("failed to persist cached-microdesc-consensus", "error", err)
	}
}
