package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	cachedCertsFileName   = "cached-certs"
	maxCachedCertsBytes   = 2 << 20
	maxCachedCertsEntries = 32
)

// EnableCertDiskCache 把权威证书落到 dataDir/cached-certs（C Tor 同名格式）。
// dataDir 为空则关闭落盘。文件缺失或损坏时从空缓存继续，不让客户端启动失败。
func (c *Client) EnableCertDiskCache(dataDir string) error {
	if c == nil || c.certCache == nil {
		return fmt.Errorf("directory client not initialized")
	}
	return c.certCache.enableDisk(dataDir)
}

// CachedAuthorityCertCount 返回内存中已缓存（含磁盘加载）的权威证书数量。
func (c *Client) CachedAuthorityCertCount() int {
	if c == nil || c.certCache == nil {
		return 0
	}
	c.certCache.mu.RLock()
	defer c.certCache.mu.RUnlock()
	return len(c.certCache.certs)
}

// AuthorityCertHTTPFetches 返回本客户端实际发起的 /tor/keys/fp HTTP 次数。
func (c *Client) AuthorityCertHTTPFetches() uint64 {
	if c == nil || c.certCache == nil {
		return 0
	}
	return c.certCache.keyFetches.Load()
}

func (c *AuthorityCertCache) enableDisk(dataDir string) error {
	if dataDir == "" {
		c.mu.Lock()
		c.diskPath = ""
		c.mu.Unlock()
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create cert cache dir: %w", err)
	}
	path := filepath.Join(dataDir, cachedCertsFileName)
	c.mu.Lock()
	c.diskPath = path
	c.mu.Unlock()
	if err := c.loadFromDisk(); err != nil {
		c.logger.Warn("cached-certs load failed; starting with empty disk cache", "error", err)
	}
	return nil
}

func (c *AuthorityCertCache) loadFromDisk() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.diskPath == "" {
		return nil
	}
	data, err := os.ReadFile(c.diskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) > maxCachedCertsBytes {
		return fmt.Errorf("cached-certs too large (%d bytes)", len(data))
	}

	parts := splitDirKeyCertificates(string(data))
	if len(parts) == 0 {
		return fmt.Errorf("cached-certs has no dir-key-certificate-version")
	}
	if len(parts) > maxCachedCertsEntries {
		return fmt.Errorf("cached-certs has too many entries (%d)", len(parts))
	}

	loaded := 0
	for _, part := range parts {
		cert, err := parseOneAuthorityCert(part)
		if err != nil {
			c.logger.Debug("skip unreadable cached cert", "error", err)
			continue
		}
		id := strings.ToUpper(cert.Identity)
		if !isKnownAuthority(id) {
			c.logger.Debug("skip cached cert for unknown authority", "identity", id)
			continue
		}
		if err := validateAuthorityCert(cert, id, ""); err != nil {
			c.logger.Debug("skip invalid or expired cached cert", "identity", id, "error", err)
			continue
		}
		if existing, ok := c.certs[id]; ok {
			if !cert.Published.After(existing.Published) && !cert.ExpiresAt.After(existing.ExpiresAt) {
				continue
			}
		}
		cert.FetchedAt = time.Now()
		c.certs[id] = cert
		loaded++
	}
	if loaded > 0 {
		c.logger.Info("loaded authority certificates from disk", "count", loaded, "path", c.diskPath)
	}
	return nil
}

func (c *AuthorityCertCache) persistToDisk() {
	c.mu.RLock()
	path := c.diskPath
	ids := make([]string, 0, len(c.certs))
	for id := range c.certs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var parts []string
	for _, id := range ids {
		cert := c.certs[id]
		if cert == nil || strings.TrimSpace(cert.raw) == "" {
			continue
		}
		if !isKnownAuthority(cert.Identity) {
			continue
		}
		if err := validateAuthorityCert(cert, cert.Identity, ""); err != nil {
			continue
		}
		raw := cert.raw
		if !strings.HasSuffix(raw, "\n") {
			raw += "\n"
		}
		parts = append(parts, raw)
	}
	c.mu.RUnlock()
	if path == "" || len(parts) == 0 {
		return
	}

	body := strings.Join(parts, "")
	if len(body) > maxCachedCertsBytes {
		c.logger.Warn("refusing to write oversized cached-certs")
		return
	}
	if err := writeFileAtomic(path, []byte(body), 0o600); err != nil {
		c.logger.Warn("failed to persist cached-certs", "error", err)
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cached-certs-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
