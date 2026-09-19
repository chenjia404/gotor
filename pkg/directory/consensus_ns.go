package directory

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
)

// FetchNSConsensusDocument 拉取并验签 ns flavor 共识，写入 cached-consensus。
// 不改 lastConsensusRaw / 选路 relay 表。失败时若磁盘已有已验签文档则保留。
func (c *Client) FetchNSConsensusDocument(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("directory client not initialized")
	}
	if !c.NSConsensusCacheEnabled() {
		return fmt.Errorf("ns consensus disk cache disabled")
	}

	diskOK := false
	if c.copyNSConsensusRaw() == "" {
		if err := c.tryLoadNSConsensusDisk(ctx); err == nil {
			diskOK = true
		}
	} else {
		diskOK = true
	}

	var lastErr error
	for _, authority := range c.authorities {
		nsURL := NSConsensusURL(authority)
		if err := c.fetchNSFromAuthority(ctx, nsURL); err != nil {
			c.logger.Warn("Failed to fetch ns consensus from authority", "authority", nsURL, "error", err)
			lastErr = err
			continue
		}
		c.logger.Info("stored ns consensus for DirCache", "authority", nsURL)
		return nil
	}
	if diskOK {
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no directory authorities")
	}
	return fmt.Errorf("failed to fetch ns consensus: %w", lastErr)
}

func (c *Client) tryLoadNSConsensusDisk(ctx context.Context) error {
	c.mu.RLock()
	path := c.nsDiskPath
	c.mu.RUnlock()
	if path == "" {
		return fmt.Errorf("ns consensus disk cache disabled")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- CacheDirectory 由操作者配置
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxCachedConsensusBytes {
		return fmt.Errorf("cached ns consensus empty or too large")
	}
	if err := c.acceptNSConsensus(ctx, string(data)); err != nil {
		c.logger.Info("cached-consensus rejected", "error", err)
		return err
	}
	c.logger.Info("loaded ns consensus from disk", "path", path)
	return nil
}

func (c *Client) fetchNSFromAuthority(ctx context.Context, authorityURL string) error {
	fromHex := c.cachedNSSignedSHA3()
	if fromHex != "" {
		raw, err := c.httpGetConsensus(ctx, authorityURL, fromHex)
		if err == nil {
			doc, aerr := c.resolveNSConsensusPayload(raw)
			if aerr == nil {
				if ierr := c.acceptNSConsensus(ctx, doc); ierr == nil {
					return nil
				} else {
					c.logger.Warn("applied or received ns consensus rejected; falling back to full document", "error", ierr)
				}
			} else {
				c.logger.Warn("ns consensus diff apply failed; falling back to full document", "error", aerr)
			}
		}
	}

	raw, err := c.httpGetConsensus(ctx, authorityURL, "")
	if err != nil {
		return err
	}
	if isConsensusDiffDocument(raw) {
		return fmt.Errorf("authority returned consensus diff on full-document ns request")
	}
	return c.acceptNSConsensus(ctx, raw)
}

func (c *Client) resolveNSConsensusPayload(raw string) (string, error) {
	if !isConsensusDiffDocument(raw) {
		return raw, nil
	}
	cached := c.copyNSConsensusRaw()
	if cached == "" {
		return "", fmt.Errorf("received ns consensus diff without cached ns consensus")
	}
	return applyConsensusDiff(cached, raw)
}

func (c *Client) acceptNSConsensus(ctx context.Context, doc string) error {
	doc = stripConsensusPreamble(doc)
	flavor, ok := DetectConsensusFlavor(doc)
	if !ok || flavor != FlavorNS {
		return fmt.Errorf("document is not ns flavor consensus")
	}
	signedSHA3, err := c.verifyConsensusDocument(ctx, doc)
	if err != nil {
		return err
	}
	c.rememberVerifiedNSConsensus(doc, signedSHA3)
	c.persistNSConsensusDisk(doc)
	return nil
}

// verifyConsensusDocument 验签共识，不写入选路缓存。signedSHA3 为 signed body 的 SHA3-256 hex。
func (c *Client) verifyConsensusDocument(ctx context.Context, doc string) (string, error) {
	signedBody, err := extractConsensusSignedBody(doc)
	if err != nil {
		return "", fmt.Errorf("consensus signed-body: %w", err)
	}
	_, metadata, err := c.parseConsensusWithMetadata(bytes.NewReader(signedBody))
	if err != nil {
		return "", fmt.Errorf("failed to parse consensus: %w", err)
	}
	sigSection, err := consensusSignatureSection(doc)
	if err != nil {
		return "", fmt.Errorf("consensus signatures: %w", err)
	}
	_, sigMeta, err := c.parseConsensusWithMetadata(strings.NewReader(sigSection))
	if err != nil {
		return "", fmt.Errorf("failed to parse consensus signatures: %w", err)
	}
	metadata.Signatures = sigMeta.Signatures
	metadata.SignatureCount = sigMeta.SignatureCount
	metadata.AuthorityCount = sigMeta.AuthorityCount
	if err := ValidateConsensusMetadata(metadata); err != nil {
		return "", fmt.Errorf("consensus validation failed: %w", err)
	}
	c.prefetchAuthorityCerts(ctx, metadata)
	if err := c.VerifyConsensusSignatures(ctx, signedBody, metadata); err != nil {
		return "", fmt.Errorf("consensus signature verification failed: %w", err)
	}
	return sha3_256Hex(signedBody), nil
}

func (c *Client) rememberVerifiedNSConsensus(doc, signedSHA3 string) {
	c.mu.Lock()
	c.nsLastRaw = doc
	c.nsLastSignedSHA3Hex = signedSHA3
	c.mu.Unlock()
}

func (c *Client) copyNSConsensusRaw() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nsLastRaw
}

func (c *Client) cachedNSSignedSHA3() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nsLastSignedSHA3Hex
}
