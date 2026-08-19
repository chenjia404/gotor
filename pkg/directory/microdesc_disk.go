package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	cachedMicrodescsName     = "cached-microdescs"
	cachedMicrodescsNewName  = "cached-microdescs.new"
	maxCachedMicrodescsBytes = 32 << 20
)

// EnableMicrodescDiskCache 加载 cached-microdescs + cached-microdescs.new。
func (c *Client) EnableMicrodescDiskCache(cacheDir string) error {
	if c == nil {
		return fmt.Errorf("directory client not initialized")
	}
	if cacheDir == "" {
		c.mu.Lock()
		c.microdescDisk = nil
		c.mu.Unlock()
		return nil
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("create microdesc cache dir: %w", err)
	}
	md := &microdescDiskCache{
		dir:      cacheDir,
		byDigest: make(map[string][]byte),
	}
	if err := md.load(); err != nil {
		c.logger.Warn("microdesc disk cache load failed; starting empty", "error", err)
	}
	c.mu.Lock()
	c.microdescDisk = md
	c.mu.Unlock()
	return nil
}

type microdescDiskCache struct {
	dir      string
	mu       sync.RWMutex
	byDigest map[string][]byte
}

func (m *microdescDiskCache) load() error {
	for _, name := range []string{cachedMicrodescsName, cachedMicrodescsNewName} {
		path := filepath.Join(m.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if len(data) > maxCachedMicrodescsBytes {
			return fmt.Errorf("%s too large", name)
		}
		m.ingestRaw(data)
	}
	return nil
}

func (m *microdescDiskCache) ingestRaw(data []byte) {
	docs := splitAnnotatedMicrodescs(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byDigest == nil {
		m.byDigest = make(map[string][]byte)
	}
	for _, doc := range docs {
		body := stripAnnotationLines(doc)
		if len(bytesTrimSpace(body)) == 0 {
			continue
		}
		if !strings.HasSuffix(string(body), "\n") {
			body = append(body, '\n')
		}
		digest := microdescriptorDigest(body)
		m.byDigest[digest] = body
	}
}

func splitAnnotatedMicrodescs(data []byte) [][]byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !strings.Contains(text, "onion-key\n") {
		return splitMicrodescriptorDocuments(data)
	}
	parts := strings.Split(text, "onion-key\n")
	var docs [][]byte
	prefix := ""
	for i, part := range parts {
		if i == 0 {
			prefix = part
			continue
		}
		doc := prefix + "onion-key\n" + part
		prefix = ""
		if !strings.HasSuffix(doc, "\n") {
			doc += "\n"
		}
		docs = append(docs, []byte(doc))
	}
	return docs
}

func stripAnnotationLines(data []byte) []byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	raw := strings.Split(text, "\n")
	var lines []string
	for _, line := range raw {
		if strings.HasPrefix(line, "@") {
			continue
		}
		lines = append(lines, line)
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func (m *microdescDiskCache) lookup(digest string) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.byDigest[digest]...)
}

func (m *microdescDiskCache) remember(digest string, body []byte) {
	m.mu.Lock()
	if m.byDigest == nil {
		m.byDigest = make(map[string][]byte)
	}
	m.byDigest[digest] = append([]byte(nil), body...)
	m.mu.Unlock()
}

func (m *microdescDiskCache) appendNew(body []byte, avoidDisk bool) {
	if m == nil || avoidDisk || len(body) == 0 {
		return
	}
	path := filepath.Join(m.dir, cachedMicrodescsNewName)
	stamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	var buf strings.Builder
	fmt.Fprintf(&buf, "@last-listed %s\n", stamp)
	buf.Write(body)
	if !strings.HasSuffix(buf.String(), "\n") {
		buf.WriteByte('\n')
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(buf.String())
	_ = f.Close()
}

func (c *Client) applyMicrodescsFromDisk(relays []*Relay) []*Relay {
	c.mu.RLock()
	md := c.microdescDisk
	c.mu.RUnlock()
	if md == nil {
		return relays
	}
	var needed []*Relay
	for _, r := range relays {
		if r == nil || r.HasExtendKeys() {
			continue
		}
		body := md.lookup(r.MicrodescDigest)
		if len(body) == 0 {
			needed = append(needed, r)
			continue
		}
		fields := parseMicrodescriptorFields(body)
		if len(fields.ntorKey) != 32 {
			needed = append(needed, r)
			continue
		}
		r.NtorOnionKey = fields.ntorKey
		if len(fields.identityKey) == 32 {
			r.IdentityKey = fields.identityKey
		}
		if len(fields.family) > 0 {
			r.Family = fields.family
		}
		if len(fields.familyIDs) > 0 {
			r.FamilyIDs = fields.familyIDs
		}
		if fields.policy != nil {
			r.ExitPolicy = fields.policy
		}
		if fields.policyIPv6 != nil {
			r.ExitPolicyIPv6 = fields.policyIPv6
		}
	}
	return needed
}

func (c *Client) persistFetchedMicrodescs(relays []*Relay) {
	c.mu.RLock()
	md := c.microdescDisk
	avoid := c.avoidDiskWrites
	c.mu.RUnlock()
	if md == nil || avoid {
		return
	}
	for _, r := range relays {
		if r == nil || r.MicrodescDigest == "" || len(r.microdescRaw) == 0 {
			continue
		}
		if existing := md.lookup(r.MicrodescDigest); len(existing) > 0 {
			continue
		}
		// 磁盘缓存只存从网络拉到的原始文档；若没有 raw 则跳过。
		if raw := r.microdescRaw; len(raw) > 0 {
			body := stripAnnotationLines(raw)
			if !strings.HasSuffix(string(body), "\n") {
				body = append(body, '\n')
			}
			md.remember(r.MicrodescDigest, body)
			md.appendNew(body, avoid)
		}
	}
}
