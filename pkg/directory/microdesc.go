package directory

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// FetchMicrodescriptors 从 directory cache / authority 批量拉取 microdescriptor，
// 并填充 RSA/Ed25519/ntor 密钥。部分 batch 失败不会中止，但若最终 0 个 relay 有密钥则返回 error。
func (c *Client) FetchMicrodescriptors(ctx context.Context, relays []*Relay) error {
	digestMap := make(map[string][]*Relay)
	for _, relay := range relays {
		if relay.MicrodescDigest != "" {
			digestMap[relay.MicrodescDigest] = append(digestMap[relay.MicrodescDigest], relay)
		}
	}
	if len(digestMap) == 0 {
		c.logger.Warn("No microdescriptor digests found in consensus")
		return nil
	}

	digests := make([]string, 0, len(digestMap))
	for digest := range digestMap {
		digests = append(digests, digest)
	}

	c.logger.Info("Fetching microdescriptors", "count", len(digests))

	const batchSize = 32
	const workers = 8
	jobs := make(chan []string)
	var wg sync.WaitGroup
	var failCount atomic.Int64

	sources := c.microdescSources(relays)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range jobs {
				if err := c.fetchMicrodescriptorBatch(ctx, batch, digestMap, sources); err != nil {
					c.logger.Warn("Failed to fetch microdescriptor batch", "error", err, "size", len(batch))
					failCount.Add(1)
				}
			}
		}()
	}

	for i := 0; i < len(digests); i += batchSize {
		end := i + batchSize
		if end > len(digests) {
			end = len(digests)
		}
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		case jobs <- digests[i:end]:
		}
	}
	close(jobs)
	wg.Wait()

	populated := 0
	for _, relay := range relays {
		if relay.HasNtorKeys() {
			populated++
		}
	}
	c.logger.Info("Microdescriptor fetch complete",
		"populated", populated,
		"total", len(relays),
		"failed_batches", failCount.Load())

	if populated == 0 {
		return fmt.Errorf("microdescriptor fetch populated 0/%d relay keys", len(relays))
	}
	return nil
}

// FetchMicrodescriptorsFor 只拉取指定 relay 的 microdescriptor（3-hop 路径用）。
func (c *Client) FetchMicrodescriptorsFor(ctx context.Context, relays []*Relay) error {
	needed := make([]*Relay, 0, len(relays))
	for _, r := range relays {
		if r == nil {
			continue
		}
		if r.MicrodescDigest == "" {
			return fmt.Errorf("relay %s missing microdescriptor digest", r.Nickname)
		}
		if !r.HasExtendKeys() {
			needed = append(needed, r)
		}
	}
	if len(needed) == 0 {
		return nil
	}

	digestMap := make(map[string][]*Relay)
	digests := make([]string, 0, len(needed))
	for _, r := range needed {
		digestMap[r.MicrodescDigest] = append(digestMap[r.MicrodescDigest], r)
		digests = append(digests, r.MicrodescDigest)
	}

	sources := c.microdescSources(needed)
	if err := c.fetchMicrodescriptorBatch(ctx, digests, digestMap, sources); err != nil {
		return err
	}
	for _, r := range needed {
		if !r.HasNtorKeys() {
			return fmt.Errorf("relay %s (%s) still missing ntor keys after microdescriptor fetch", r.Nickname, r.FingerprintHex)
		}
	}
	return nil
}

func (c *Client) microdescSources(relays []*Relay) []string {
	seen := make(map[string]struct{})
	var sources []string

	add := func(base string) {
		base = strings.TrimRight(base, "/")
		if base == "" {
			return
		}
		if _, ok := seen[base]; ok {
			return
		}
		seen[base] = struct{}{}
		sources = append(sources, base)
	}

	for _, authority := range c.authorities {
		base := strings.TrimSuffix(authority, "/tor/status-vote/current/consensus-microdesc")
		base = strings.TrimSuffix(base, "/tor/status-vote/current/consensus")
		add(base)
	}

	// 共识中的 V2Dir cache，优先于 authority（带宽更好）
	cacheCount := 0
	for _, r := range relays {
		if cacheCount >= 16 {
			break
		}
		if r.DirPort > 0 && r.HasFlag("V2Dir") && r.IsRunning() && r.Address != "" {
			add(fmt.Sprintf("http://%s:%d", r.Address, r.DirPort))
			cacheCount++
		}
	}
	return sources
}

func (c *Client) fetchMicrodescriptorBatch(ctx context.Context, digests []string, digestMap map[string][]*Relay, sources []string) error {
	digestList := strings.Join(digests, "-")
	urlPath := "/tor/micro/d/" + digestList

	var lastErr error
	for _, base := range sources {
		md, err := c.fetchMicrodescriptorsFromAuthority(ctx, base+urlPath)
		if err != nil {
			lastErr = err
			continue
		}
		if err := c.parseMicrodescriptors(md, digestMap); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no directory sources available")
	}
	return fmt.Errorf("failed to fetch microdescriptors from any authority: %w", lastErr)
}

func (c *Client) fetchMicrodescriptorsFromAuthority(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "deflate, gzip")
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch microdescriptors: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Error("Failed to close response body", "function", "fetchMicrodescriptorsFromAuthority", "error", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	case "deflate":
		zlibReader, err := zlib.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader: %w", err)
		}
		defer zlibReader.Close()
		reader = zlibReader
	}
	return io.ReadAll(reader)
}

// parseMicrodescriptors 按 dir-spec 把每个完整 microdescriptor 文档哈希后匹配共识 m 行。
func (c *Client) parseMicrodescriptors(data []byte, digestMap map[string][]*Relay) error {
	docs := splitMicrodescriptorDocuments(data)
	matched := 0
	for _, doc := range docs {
		digest := microdescriptorDigest(doc)
		relays, ok := digestMap[digest]
		if !ok {
			// 部分 authority 在 m 行带 padding
			padded := base64.StdEncoding.EncodeToString(mustSHA256(doc))
			relays, ok = digestMap[padded]
		}
		if !ok {
			continue
		}
		ntorKey, identityKey, family := parseMicrodescriptorFields(doc)
		if len(ntorKey) != 32 {
			continue
		}
		for _, relay := range relays {
			relay.NtorOnionKey = ntorKey
			if len(identityKey) == 32 {
				relay.IdentityKey = identityKey
			}
			if len(family) > 0 {
				relay.Family = family
			}
		}
		matched++
	}
	c.logger.Debug("Parsed microdescriptors", "documents", len(docs), "matched", matched)
	return nil
}

func splitMicrodescriptorDocuments(data []byte) [][]byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	parts := strings.Split(text, "onion-key\n")
	docs := make([][]byte, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		doc := "onion-key\n" + part
		if !strings.HasSuffix(doc, "\n") {
			doc += "\n"
		}
		docs = append(docs, []byte(doc))
	}
	return docs
}

func microdescriptorDigest(doc []byte) string {
	sum := sha256.Sum256(doc)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func mustSHA256(doc []byte) []byte {
	sum := sha256.Sum256(doc)
	return sum[:]
}

func parseMicrodescriptorFields(doc []byte) (ntorKey, identityKey []byte, family []string) {
	scanner := bufio.NewScanner(strings.NewReader(string(doc)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "ntor-onion-key":
			if len(fields) >= 2 {
				if key, err := decodeTorBase64(fields[1]); err == nil && len(key) == 32 {
					ntorKey = key
				}
			}
		case "id":
			if len(fields) >= 3 && fields[1] == "ed25519" && fields[2] != "none" {
				if key, err := decodeTorBase64(fields[2]); err == nil && len(key) == 32 {
					identityKey = key
				}
			}
		case "family":
			if len(fields) > 1 {
				family = append([]string{}, fields[1:]...)
			}
		}
	}
	return ntorKey, identityKey, family
}

func decodeTorBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("invalid base64")
}

// DecodeRSAIdentity 把共识 r 行 identity（无 padding base64）解码为 20 字节 NODEID。
func DecodeRSAIdentity(identity string) ([]byte, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return nil, fmt.Errorf("empty RSA identity")
	}
	if b, err := decodeTorBase64(identity); err == nil && len(b) == 20 {
		return b, nil
	}
	if len(identity) == 40 {
		b, err := hex.DecodeString(identity)
		if err == nil && len(b) == 20 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid RSA identity %q", identity)
}

func fingerprintHex(id []byte) string {
	return strings.ToUpper(hex.EncodeToString(id))
}

// calculateMicrodescriptorDigest 保留给单元测试：按规范哈希完整文档。
func (c *Client) calculateMicrodescriptorDigest(lines []string) string {
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return microdescriptorDigest([]byte(content))
}
