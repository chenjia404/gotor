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

// EnableNSConsensusDiskCache 启用 CacheDirectory/cached-consensus（ns flavor）。
// 只给 DirCache 对外服务；不得写入 lastConsensusRaw / 选路用的 microdesc 缓存。
func (c *Client) EnableNSConsensusDiskCache(cacheDir string) error {
	if c == nil {
		return fmt.Errorf("directory client not initialized")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cacheDir == "" {
		c.nsDiskPath = ""
		return nil
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("create ns consensus cache dir: %w", err)
	}
	c.nsDiskPath = filepath.Join(cacheDir, cachedNSConsensusName)
	return nil
}

// NSConsensusCacheEnabled 报告是否已启用 ns flavor 落盘（中继 DirCache）。
func (c *Client) NSConsensusCacheEnabled() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nsDiskPath != ""
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
	// 换共识时把上一份推进历史库（最多 72 小时），供落后多期的客户端拿 limited-ed。
	if flavor, ok := DetectConsensusFlavor(doc); ok && flavor != FlavorMicrodesc {
		c.logger.Warn("refusing to write non-microdesc consensus into cached-microdesc-consensus")
		return
	}
	if existing, err := os.ReadFile(path); err == nil && len(existing) > 0 && len(existing) <= maxCachedConsensusBytes { // #nosec G304 -- CacheDirectory 由操作者配置
		oldFrom := consensusDiffFromDigest(string(existing))
		newFrom := consensusDiffFromDigest(doc)
		if hexDigestEqual(oldFrom, newFrom) {
			return
		}
		persistConsensusHistory(filepath.Dir(path), existing, doc)
	}
	if err := writeFileAtomic(path, []byte(doc), 0o600); err != nil {
		c.logger.Warn("failed to persist cached-microdesc-consensus", "error", err)
		return
	}
	if err := RebuildConsensusDiffLibrary(filepath.Dir(path), FlavorMicrodesc, doc); err != nil && c.logger != nil {
		c.logger.Warn("failed to rebuild microdesc consdiff library", "error", err)
	}
}

func (c *Client) persistNSConsensusDisk(doc string) {
	c.mu.RLock()
	path := c.nsDiskPath
	avoid := c.avoidDiskWrites
	c.mu.RUnlock()
	if avoid || path == "" || strings.TrimSpace(doc) == "" {
		return
	}
	if len(doc) > maxCachedConsensusBytes {
		c.logger.Warn("refusing to write oversized cached-consensus")
		return
	}
	if flavor, ok := DetectConsensusFlavor(doc); !ok || flavor != FlavorNS {
		c.logger.Warn("refusing to write non-ns consensus into cached-consensus")
		return
	}
	if existing, err := os.ReadFile(path); err == nil && len(existing) > 0 && len(existing) <= maxCachedConsensusBytes { // #nosec G304 -- CacheDirectory 由操作者配置
		oldFrom := consensusDiffFromDigest(string(existing))
		newFrom := consensusDiffFromDigest(doc)
		if hexDigestEqual(oldFrom, newFrom) {
			return
		}
		persistConsensusHistoryFlavor(filepath.Dir(path), FlavorNS, existing, doc)
	}
	if err := writeFileAtomic(path, []byte(doc), 0o600); err != nil {
		c.logger.Warn("failed to persist cached-consensus", "error", err)
		return
	}
	if err := RebuildConsensusDiffLibrary(filepath.Dir(path), FlavorNS, doc); err != nil && c.logger != nil {
		c.logger.Warn("failed to rebuild ns consdiff library", "error", err)
	}
}
