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
	cachedMicrodescsName    = "cached-microdescs"
	cachedMicrodescsNewName = "cached-microdescs.new"
	// 全网 microdesc 加上 @last-listed 注解后已经超过 32MiB。
	// 到顶就整份拒载，进程再把同一批追加进 .new，文件只增不减。
	defaultMaxCachedMicrodescsBytes  = 128 << 20
	defaultMicrodescJournalCompactAt = 8 << 20
)

var (
	maxCachedMicrodescsBytes  = defaultMaxCachedMicrodescsBytes
	microdescJournalCompactAt = defaultMicrodescJournalCompactAt
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
	var skipped []string
	for _, name := range []string{cachedMicrodescsName, cachedMicrodescsNewName} {
		path := filepath.Join(m.dir, name)
		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if fi.Size() > int64(maxCachedMicrodescsBytes) {
			skipped = append(skipped, name)
			continue
		}
		data, err := os.ReadFile(path) // #nosec G304 -- CacheDirectory 固定文件名
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		m.ingestRaw(data)
	}
	m.mu.Lock()
	loaded := len(m.byDigest)
	journal := filepath.Join(m.dir, cachedMicrodescsNewName)
	needCompact := false
	if fi, err := os.Stat(journal); err == nil && fi.Size() > 0 {
		needCompact = true
	}
	if len(skipped) > 0 {
		needCompact = true
	}
	if loaded > 0 && needCompact {
		m.compactLocked()
	}
	m.mu.Unlock()
	if loaded == 0 && len(skipped) > 0 {
		return fmt.Errorf("%s too large", skipped[0])
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
	m.mu.Lock()
	defer m.mu.Unlock()
	path := filepath.Join(m.dir, cachedMicrodescsNewName)
	if fi, err := os.Stat(path); err == nil && fi.Size() >= int64(microdescJournalCompactAt) {
		// remember 已经把正文放进 byDigest；到阈值就重写成去重后的主文件。
		m.compactLocked()
		return
	}
	m.appendJournalLocked(body)
}

func (m *microdescDiskCache) appendJournalLocked(body []byte) {
	path := filepath.Join(m.dir, cachedMicrodescsNewName)
	stamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	var buf strings.Builder
	fmt.Fprintf(&buf, "@last-listed %s\n", stamp)
	buf.Write(body)
	if !strings.HasSuffix(buf.String(), "\n") {
		buf.WriteByte('\n')
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- CacheDirectory 固定文件名
	if err != nil {
		return
	}
	_, _ = f.WriteString(buf.String())
	_ = f.Close()
}

// compactLocked 把内存里的去重文档写成 cached-microdescs，并丢掉只增不减的 .new。
// 调用方必须持有 m.mu。
func (m *microdescDiskCache) compactLocked() {
	if m == nil || m.dir == "" || len(m.byDigest) == 0 {
		return
	}
	var buf strings.Builder
	stamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	for _, body := range m.byDigest {
		if len(body) == 0 {
			continue
		}
		fmt.Fprintf(&buf, "@last-listed %s\n", stamp)
		buf.Write(body)
		if body[len(body)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	if buf.Len() == 0 {
		return
	}
	final := filepath.Join(m.dir, cachedMicrodescsName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(buf.String()), 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(final)
		if err2 := os.Rename(tmp, final); err2 != nil {
			_ = os.Remove(tmp)
			return
		}
	}
	_ = os.Remove(filepath.Join(m.dir, cachedMicrodescsNewName))
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

// HydrateRelayMicrodescs 用磁盘缓存补齐 ntor 与 Ed25519。
// HSDir 哈希环必须用全网目录的 Ed25519 身份；只给建路过的节点补密钥时，环是残的，负责目录会 404。
func (c *Client) HydrateRelayMicrodescs(relays []*Relay) int {
	if c == nil {
		return 0
	}
	c.applyMicrodescsFromDisk(relays)
	n := 0
	for _, r := range relays {
		if r != nil && len(r.IdentityKey) == 32 {
			n++
		}
	}
	return n
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
