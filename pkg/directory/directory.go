// Package directory provides Tor directory protocol functionality.
// This package handles fetching and parsing directory consensus documents and router descriptors.
package directory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

const (
	// Consensus validation thresholds (SEC-004, SEC-014)
	maxMalformedEntryRate = 10 // Reject if >10% of entries are malformed
	maxPortParseErrorRate = 20 // Warn if >20% of entries have port parse errors

	// SPEC-003: Enhanced consensus signature validation thresholds
	// Per dir-spec.txt section 3.4 (Voting and consensus signature requirements)
	// A valid consensus requires signatures from a majority of directory authorities
	minDirectoryAuthorities = 5                // Minimum authorities for valid consensus (5 of 9)
	minSignatureThreshold   = 5                // Minimum valid signatures required (proper quorum)
	maxClockSkew            = 30 * time.Minute // Maximum allowed clock skew for consensus timestamps

	// 共识正文上限（整份或 apply 后）。真实 microdesc 共识约 1–3MB。
	maxConsensusDownloadBytes = 16 << 20
)

// DefaultAuthorities is the default directory authority addresses (hardcoded fallback directories)
// Using HTTP instead of HTTPS for better compatibility with IP-based authorities
// The Tor consensus is cryptographically signed, so transport encryption is not critical
// Using consensus-microdesc format (consensus-method 33) which includes "m" lines with microdescriptor digests
var DefaultAuthorities = []string{
	"http://128.31.0.39:9231/tor/status-vote/current/consensus-microdesc", // moria1
	"http://217.196.147.77/tor/status-vote/current/consensus-microdesc",   // tor26
	"http://45.66.35.11/tor/status-vote/current/consensus-microdesc",      // dizum
	"http://131.188.40.189/tor/status-vote/current/consensus-microdesc",   // gabelmoo
	"http://193.23.244.244/tor/status-vote/current/consensus-microdesc",   // dannenberg
	"http://199.58.81.140/tor/status-vote/current/consensus-microdesc",    // longclaw
	"http://204.13.164.118/tor/status-vote/current/consensus-microdesc",   // bastet
	"http://216.218.219.41/tor/status-vote/current/consensus-microdesc",   // faravahar
}

// DirectoryAuthority represents a known Tor directory authority (SPEC-003)
// These are the official Tor directory authorities as of January 2026
// Source: https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/app/config/auth_dirs.inc
type DirectoryAuthority struct {
	Nickname string // Human-readable authority name
	V3Ident  string // SHA-1 fingerprint of authority's long-term v3 identity key (40 hex chars)
	Address  string // IP address and ports
}

// KnownAuthorities contains the list of official Tor directory authorities (SPEC-003)
// These authorities are responsible for creating and signing the network consensus
// The v3ident fingerprints are used to verify consensus signatures
//
// IMPORTANT: This list should be updated if the Tor Project adds or removes authorities
// Current as of: January 2026
// Reference: https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/app/config/auth_dirs.inc
var KnownAuthorities = []DirectoryAuthority{
	{
		Nickname: "moria1",
		V3Ident:  "F533C81CEF0BC0267857C99B2F471ADF249FA232",
		Address:  "128.31.0.39:9231",
	},
	{
		Nickname: "tor26",
		V3Ident:  "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
		Address:  "217.196.147.77:80",
	},
	{
		Nickname: "dizum",
		V3Ident:  "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
		Address:  "45.66.35.11:80",
	},
	{
		Nickname: "gabelmoo",
		V3Ident:  "ED03BB616EB2F60BEC80151114BB25CEF515B226",
		Address:  "131.188.40.189:80",
	},
	{
		Nickname: "dannenberg",
		V3Ident:  "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
		Address:  "193.23.244.244:80",
	},
	{
		Nickname: "maatuska",
		V3Ident:  "49015F787433103580E3B66A1707A00E60F2D15B",
		Address:  "171.25.193.9:443",
	},
	{
		Nickname: "longclaw",
		V3Ident:  "23D15D965BC35114467363C165C4F724B64B4F66",
		Address:  "199.58.81.140:80",
	},
	{
		Nickname: "bastet",
		V3Ident:  "27102BC123E7AF1D4741AE047E160C91ADC76B21",
		Address:  "204.13.164.118:80",
	},
	{
		Nickname: "faravahar",
		V3Ident:  "70849B868D606BAECFB6128C5E3D782029AA394F",
		Address:  "216.218.219.41:80",
	},
}

// Relay represents a Tor relay from the consensus
type Relay struct {
	Nickname        string
	Fingerprint     string
	Address         string
	ORPort          int
	IPv6            string // 共识/microdesc a 行的第一个 IPv6 OR 地址（不含方括号）
	IPv6Port        int    // 对应 IPv6 ORPort
	DirPort         int
	Flags           []string
	Published       time.Time
	RSAIdentity     []byte             // 20-byte SHA-1 of RSA identity (ntor NODEID)
	FingerprintHex  string             // 40-char uppercase hex of RSAIdentity (CERTS / logs)
	IdentityKey     []byte             // Ed25519 identity key (32 bytes)
	NtorOnionKey    []byte             // Curve25519 ntor onion key (32 bytes)
	MicrodescDigest string             // SHA256 digest of microdescriptor (base64, no padding)
	microdescRaw    []byte             // 最近一次匹配的 microdescriptor 原文（落盘用）
	Family          []string           // microdesc / descriptor 的 family 列表（$HEX 或 nickname）
	FamilyIDs       []string           // microdesc family-ids（Desc=4 / happy families）
	Bandwidth       uint64             // Advertised bandwidth in bytes/sec (from "w" line) - path-spec.txt §2.2
	ExitPolicy      *ExitPolicySummary // 共识或 microdescriptor 的 p 行（IPv4 摘要）
	ExitPolicyIPv6  *ExitPolicySummary // microdescriptor 的 p6 / descriptor 的 ipv6-policy
	ExitRules       *ExitPolicy        // server descriptor 完整 accept/reject 列表
	Protocols       ProtoVersions      // 共识 pr 行（Relay=4 / FlowCtrl=2）
}

// Client provides directory protocol operations
type Client struct {
	httpClient          *http.Client
	logger              *logger.Logger
	authorities         []string
	certCache           *AuthorityCertCache // Certificate cache for signature verification
	mu                  sync.RWMutex
	lastParams          map[string]int // 最近一次验签成功的共识 params（给 FlowCtrl=2）
	lastConsensusRaw    string         // 验签成功的整份共识（给 DirCache=2 diff）
	lastSignedSHA3Hex   string         // 上述文档 signed part 的 SHA3-256 hex
	lastFetchUsedDiff   bool           // 最近一次成功 ingest 是否来自 limited-ed diff
	sharedRandCurrent   []byte         // shared-rand-current-value（32 字节）
	sharedRandPrev      []byte         // shared-rand-previous-value（32 字节）
	consensusValidAfter time.Time
	consensusDiskPath   string // CacheDirectory/cached-microdesc-consensus
	avoidDiskWrites     bool
	microdescDisk       *microdescDiskCache
}

// AuthorityCertCache caches authority signing certificates for consensus verification
type AuthorityCertCache struct {
	mu         sync.RWMutex
	certs      map[string]*AuthorityCert // Key: identity fingerprint (v3ident)
	diskPath   string                    // DataDirectory/cached-certs；空则不落盘
	logger     *logger.Logger
	keyFetches atomic.Uint64 // 实际发起的 /tor/keys/fp HTTP 次数（验收用）
}

// AuthorityCert 是一份权威密钥证书（dir-key-certificate-version 3）。
//
// Identity / IdentityKey 对应 V3Ident（SHA1(PKCS1(identity))）。
// SigningKey 对应共识 directory-signature 的 signing-key-digest。
type AuthorityCert struct {
	Identity    string         // SHA-1 fingerprint of authority's identity key (v3ident)
	IdentityKey *rsa.PublicKey // 长期 identity 公钥
	SigningKey  *rsa.PublicKey // 中期 signing 公钥
	ExpiresAt   time.Time      // Certificate expiration time
	FetchedAt   time.Time      // When this cert was fetched
	Published   time.Time      // dir-key-published
	raw         string         // 原始证书文档，用于 certification / crosscert
}

// NewClient creates a new directory client
func NewClient(log *logger.Logger) *Client {
	if log == nil {
		log = logger.NewDefault()
	}

	// Create HTTP client with custom transport
	// Use TLS config that skips verification for IP-based authorities
	// This is acceptable because consensus documents are cryptographically signed
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Required for IP-based directory authorities
		},
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:   45 * time.Second,
			Transport: transport,
		},
		logger:      log.Component("directory"),
		authorities: DefaultAuthorities,
		certCache: &AuthorityCertCache{
			certs:  make(map[string]*AuthorityCert),
			logger: log.Component("certcache"),
		},
	}
}

// FetchConsensus fetches the network consensus from directory authorities
// and populates relay cryptographic keys from microdescriptors (SPEC-001)
func (c *Client) FetchConsensus(ctx context.Context) ([]*Relay, error) {
	c.logger.Info("Fetching network consensus")

	if c.copyLastConsensusRaw() == "" {
		if relays, err := c.tryLoadConsensusDisk(ctx); err == nil && len(relays) > 0 {
			return relays, nil
		}
	}

	// Try each authority until one succeeds
	var lastErr error
	for _, authority := range c.authorities {
		relays, err := c.fetchFromAuthority(ctx, authority)
		if err != nil {
			c.logger.Warn("Failed to fetch from authority", "authority", authority, "error", err)
			lastErr = err
			continue
		}

		c.logger.Info("Successfully fetched consensus", "relays", len(relays), "authority", authority)
		// 不在此处拉全网 microdesc。选路后由 FetchMicrodescriptorsFor 只拉 Guard/Middle/Exit。
		return relays, nil
	}

	return nil, fmt.Errorf("failed to fetch consensus from any authority: %w", lastErr)
}

// fetchFromAuthority fetches consensus from a specific authority
func (c *Client) fetchFromAuthority(ctx context.Context, authorityURL string) ([]*Relay, error) {
	fromHex := c.cachedSignedSHA3()
	if fromHex != "" {
		raw, err := c.httpGetConsensus(ctx, authorityURL, fromHex)
		if err == nil {
			usedDiff := isConsensusDiffDocument(raw)
			doc, aerr := c.resolveConsensusPayload(raw)
			if aerr == nil {
				relays, ierr := c.ingestConsensusDocument(ctx, doc)
				if ierr == nil {
					c.setLastFetchUsedDiff(usedDiff)
					if usedDiff {
						c.logger.Info("Consensus updated via DirCache=2 diff", "authority", authorityURL)
					}
					return relays, nil
				}
				c.logger.Warn("applied or received consensus rejected; falling back to full document", "error", ierr)
			} else {
				c.logger.Warn("consensus diff apply failed; falling back to full document", "error", aerr)
			}
		} else {
			c.logger.Debug("consensus diff request failed; falling back to full document", "error", err)
		}
	}

	raw, err := c.httpGetConsensus(ctx, authorityURL, "")
	if err != nil {
		return nil, err
	}
	if isConsensusDiffDocument(raw) {
		return nil, fmt.Errorf("authority returned consensus diff on full-document request")
	}
	relays, err := c.ingestConsensusDocument(ctx, raw)
	if err != nil {
		return nil, err
	}
	c.setLastFetchUsedDiff(false)
	return relays, nil
}

func (c *Client) setLastFetchUsedDiff(v bool) {
	c.mu.Lock()
	c.lastFetchUsedDiff = v
	c.mu.Unlock()
}

// LastFetchUsedDiff 报告最近一次成功 FetchConsensus / TryConsensusDiff 是否应用了 limited-ed diff。
func (c *Client) LastFetchUsedDiff() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFetchUsedDiff
}

// LoadVerifiedConsensusDocument 验签并缓存一份已下载的共识文档（给 DirCache=2 真实验收：
// 先灌入上一小时文档，再向权威请求 limited-ed diff）。
func (c *Client) LoadVerifiedConsensusDocument(ctx context.Context, doc string) ([]*Relay, error) {
	if isConsensusDiffDocument(doc) {
		return nil, fmt.Errorf("LoadVerifiedConsensusDocument expects a full consensus, not a diff")
	}
	relays, err := c.ingestConsensusDocument(ctx, doc)
	if err != nil {
		return nil, err
	}
	c.setLastFetchUsedDiff(false)
	return relays, nil
}

// CachedSignedSHA3Hex 返回已缓存共识 signed part 的 SHA3-256 hex（小写）；无缓存则空串。
func (c *Client) CachedSignedSHA3Hex() string {
	return c.cachedSignedSHA3()
}

// TryConsensusDiffFromAuthority 向指定权威发带 X-Or-Diff-From-Consensus 的请求。
// 用于真实验收：区分「收到 diff」「304/错误回退」「整份文档」。
// 返回 gotDiff 表示响应体是 network-status-diff；成功验签时 relays 非空。
func (c *Client) TryConsensusDiffFromAuthority(ctx context.Context, authorityURL string) (gotDiff bool, relays []*Relay, err error) {
	fromHex := c.cachedSignedSHA3()
	if fromHex == "" {
		return false, nil, fmt.Errorf("no cached consensus digest")
	}
	raw, err := c.httpGetConsensus(ctx, authorityURL, fromHex)
	if err != nil {
		return false, nil, err
	}
	gotDiff = isConsensusDiffDocument(raw)
	doc, err := c.resolveConsensusPayload(raw)
	if err != nil {
		return gotDiff, nil, err
	}
	relays, err = c.ingestConsensusDocument(ctx, doc)
	if err != nil {
		return gotDiff, nil, err
	}
	c.setLastFetchUsedDiff(gotDiff)
	return gotDiff, relays, nil
}

func (c *Client) cachedSignedSHA3() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSignedSHA3Hex
}

func (c *Client) copyLastConsensusRaw() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastConsensusRaw
}

func (c *Client) rememberVerifiedConsensus(doc, signedSHA3 string, meta *ConsensusMetadata) {
	params := map[string]int{}
	if meta != nil && meta.Params != nil {
		params = meta.Params
	}
	copied := make(map[string]int, len(params))
	for k, v := range params {
		copied[k] = v
	}
	c.mu.Lock()
	c.lastConsensusRaw = doc
	c.lastSignedSHA3Hex = signedSHA3
	c.lastParams = copied
	if meta != nil {
		c.sharedRandCurrent = append([]byte(nil), meta.SharedRandCurrent...)
		c.sharedRandPrev = append([]byte(nil), meta.SharedRandPrevious...)
		c.consensusValidAfter = meta.ValidAfter
	}
	c.mu.Unlock()
}

// SharedRandomValues 返回最近验签共识中的 current/previous SRV（各 32 字节，可空）。
func (c *Client) SharedRandomValues() (current, previous []byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.sharedRandCurrent...), append([]byte(nil), c.sharedRandPrev...)
}

// ConsensusValidAfter 返回最近验签共识的 valid-after。
func (c *Client) ConsensusValidAfter() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.consensusValidAfter
}

// resolveConsensusPayload 若是 limited ed diff 则应用到已缓存共识，否则原样返回整份文档。
func (c *Client) resolveConsensusPayload(raw string) (string, error) {
	if !isConsensusDiffDocument(raw) {
		return raw, nil
	}
	cached := c.copyLastConsensusRaw()
	if cached == "" {
		return "", fmt.Errorf("received consensus diff without cached consensus")
	}
	return applyConsensusDiff(cached, raw)
}

func (c *Client) httpGetConsensus(ctx context.Context, authorityURL, fromSHA3 string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", authorityURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	if fromSHA3 != "" {
		req.Header.Set("X-Or-Diff-From-Consensus", strings.ToLower(fromSHA3))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch consensus: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Error("Failed to close response body", "function", "httpGetConsensus", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() {
			if err := gzReader.Close(); err != nil {
				c.logger.Error("Failed to close gzip reader", "function", "httpGetConsensus", "error", err)
			}
		}()
		reader = gzReader
	case "deflate":
		zlibReader, err := zlib.NewReader(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to create zlib reader: %w", err)
		}
		defer func() {
			if err := zlibReader.Close(); err != nil {
				c.logger.Error("Failed to close zlib reader", "function", "httpGetConsensus", "error", err)
			}
		}()
		reader = zlibReader
	}

	raw, err := io.ReadAll(io.LimitReader(reader, maxConsensusDownloadBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read consensus: %w", err)
	}
	if len(raw) > maxConsensusDownloadBytes {
		return "", fmt.Errorf("consensus document exceeds %d bytes", maxConsensusDownloadBytes)
	}
	return string(raw), nil
}

func (c *Client) ingestConsensusDocument(ctx context.Context, doc string) ([]*Relay, error) {
	doc = stripConsensusPreamble(doc)
	signedBody, err := extractConsensusSignedBody(doc)
	if err != nil {
		return nil, fmt.Errorf("consensus signed-body: %w", err)
	}

	// relays / valid-* / params 只能来自签名范围，否则 MITM 可在
	// 前缀或 directory-signature 之后注入 r 行或改写有效期。
	relays, metadata, err := c.parseConsensusWithMetadata(bytes.NewReader(signedBody))
	if err != nil {
		return nil, fmt.Errorf("failed to parse consensus: %w", err)
	}

	sigSection, err := consensusSignatureSection(doc)
	if err != nil {
		return nil, fmt.Errorf("consensus signatures: %w", err)
	}
	_, sigMeta, err := c.parseConsensusWithMetadata(strings.NewReader(sigSection))
	if err != nil {
		return nil, fmt.Errorf("failed to parse consensus signatures: %w", err)
	}
	metadata.Signatures = sigMeta.Signatures
	metadata.SignatureCount = sigMeta.SignatureCount
	metadata.AuthorityCount = sigMeta.AuthorityCount

	if err := ValidateConsensusMetadata(metadata); err != nil {
		c.logger.Error("Consensus metadata validation failed", "error", err)
		return nil, fmt.Errorf("consensus validation failed: %w", err)
	}

	c.prefetchAuthorityCerts(ctx, metadata)
	if err := c.VerifyConsensusSignatures(ctx, signedBody, metadata); err != nil {
		c.logger.Error("Consensus signature verification failed", "error", err)
		return nil, fmt.Errorf("consensus signature verification failed: %w", err)
	}

	c.logger.Info("Consensus metadata and signatures validated",
		"signatures", metadata.SignatureCount,
		"valid_after", metadata.ValidAfter,
		"valid_until", metadata.ValidUntil)

	c.rememberVerifiedConsensus(doc, sha3_256Hex(signedBody), metadata)
	c.persistConsensusDisk(doc)
	return relays, nil
}

func (c *Client) storeLastParams(params map[string]int) {
	copied := make(map[string]int, len(params))
	for k, v := range params {
		copied[k] = v
	}
	c.mu.Lock()
	c.lastParams = copied
	c.mu.Unlock()
}

// LastConsensusParams 返回最近一次验签成功的共识 params 副本。
// 尚未成功拉共识时返回 nil，调用方应使用编译默认值。
func (c *Client) LastConsensusParams() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastParams == nil {
		return nil
	}
	out := make(map[string]int, len(c.lastParams))
	for k, v := range c.lastParams {
		out[k] = v
	}
	return out
}

// parseConsensus parses a consensus document and extracts relay information
func (c *Client) parseConsensus(r io.Reader) ([]*Relay, error) {
	relays, _, err := c.parseConsensusWithMetadata(r)
	return relays, err
}

// parseConsensusWithMetadata parses a consensus document and extracts both relay information and metadata (SPEC-003)
func (c *Client) parseConsensusWithMetadata(r io.Reader) ([]*Relay, *ConsensusMetadata, error) {
	var relays []*Relay
	var currentRelay *Relay
	var totalEntries int
	var malformedEntries int
	var portParseErrors int

	// SPEC-003: Metadata tracking
	metadata := &ConsensusMetadata{
		Signatures: make([]*ConsensusSignature, 0),
		Params:     make(map[string]int),
	}
	var currentSignature *ConsensusSignature
	var inSignatureBlock bool
	var signatureLines []string

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		// SPEC-003: Parse metadata header lines
		if strings.HasPrefix(line, "network-status-version ") {
			fmt.Sscanf(line, "network-status-version %d", &metadata.NetworkStatusVersion)
		}
		if strings.HasPrefix(line, "valid-after ") {
			timeStr := strings.TrimPrefix(line, "valid-after ")
			if t, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
				metadata.ValidAfter = t
			}
		}
		if strings.HasPrefix(line, "fresh-until ") {
			timeStr := strings.TrimPrefix(line, "fresh-until ")
			if t, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
				metadata.FreshUntil = t
			}
		}
		if strings.HasPrefix(line, "valid-until ") {
			timeStr := strings.TrimPrefix(line, "valid-until ")
			if t, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
				metadata.ValidUntil = t
			}
		}

		// Parse consensus parameters (dir-spec.txt §3.4.1)
		// Format: "params key=value key=value ..."
		if strings.HasPrefix(line, "params ") {
			paramsStr := strings.TrimPrefix(line, "params ")
			parseConsensusParams(paramsStr, metadata.Params)
		}

		// shared-rand-*-value NumReveals Base64Value（dir-spec）
		if strings.HasPrefix(line, "shared-rand-current-value ") {
			if v := parseSharedRandValueLine(line); len(v) == 32 {
				metadata.SharedRandCurrent = v
			}
		}
		if strings.HasPrefix(line, "shared-rand-previous-value ") {
			if v := parseSharedRandValueLine(line); len(v) == 32 {
				metadata.SharedRandPrevious = v
			}
		}

		// SPEC-003: Parse directory-signature lines
		// Format: "directory-signature" [algorithm] identity-key-digest signing-key-digest
		if strings.HasPrefix(line, "directory-signature ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// Save previous signature if any
				if currentSignature != nil {
					currentSignature.Signature = strings.Join(signatureLines, "\n")
					metadata.Signatures = append(metadata.Signatures, currentSignature)
				}

				// Start new signature
				currentSignature = &ConsensusSignature{}
				signatureLines = make([]string, 0)
				inSignatureBlock = false

				// Parse signature header
				if len(parts) == 3 {
					// Format: directory-signature identity signing
					currentSignature.Algorithm = "sha1" // Default for 2-arg format
					currentSignature.Identity = parts[1]
					currentSignature.SigningKeyDigest = parts[2]
				} else if len(parts) == 4 {
					// Format: directory-signature algorithm identity signing
					currentSignature.Algorithm = parts[1]
					currentSignature.Identity = parts[2]
					currentSignature.SigningKeyDigest = parts[3]
				}
				metadata.SignatureCount++
			}
			continue
		}

		// SPEC-003: Parse signature block
		if currentSignature != nil {
			if strings.HasPrefix(line, "-----BEGIN SIGNATURE-----") {
				inSignatureBlock = true
				signatureLines = append(signatureLines, line)
				continue
			}
			if strings.HasPrefix(line, "-----END SIGNATURE-----") {
				signatureLines = append(signatureLines, line)
				inSignatureBlock = false
				continue
			}
			if inSignatureBlock {
				signatureLines = append(signatureLines, line)
				continue
			}
		}

		// Parse "r" lines (router status entries)
		// Two formats supported:
		// 1. Regular consensus (9 fields): r nickname identity digest published IP ORPort DirPort
		// 2. Microdescriptor consensus (8 fields): r nickname identity published IP ORPort DirPort
		if strings.HasPrefix(line, "r ") {
			totalEntries++

			if currentRelay != nil {
				relays = append(relays, currentRelay)
			}

			parts := strings.Fields(line)
			if len(parts) < 8 {
				malformedEntries++
				c.logger.Debug("Skipping malformed relay entry", "line", line)
				continue // Skip malformed entries
			}

			// Determine format based on field count
			var nickname, fingerprint, address string
			var orPortIdx, dirPortIdx int

			if len(parts) >= 9 {
				// Regular consensus format (9 fields)
				nickname = parts[1]
				fingerprint = parts[2]
				// parts[3] is the digest (not used for microdescriptor-based relays)
				// parts[4] is published date
				// parts[5] is published time
				address = parts[6]
				orPortIdx = 7
				dirPortIdx = 8
			} else {
				// Microdescriptor consensus format (8 fields)
				nickname = parts[1]
				fingerprint = parts[2]
				// parts[3] is published date
				// parts[4] is published time
				address = parts[5]
				orPortIdx = 6
				dirPortIdx = 7
			}

			currentRelay = &Relay{
				Nickname:    nickname,
				Fingerprint: fingerprint,
				Address:     address,
			}
			if rsaID, err := DecodeRSAIdentity(fingerprint); err == nil {
				currentRelay.RSAIdentity = rsaID
				currentRelay.FingerprintHex = fingerprintHex(rsaID)
			}

			// Parse ORPort (track errors for SEC-014)
			if _, err := fmt.Sscanf(parts[orPortIdx], "%d", &currentRelay.ORPort); err != nil {
				portParseErrors++
				c.logger.Debug("Failed to parse ORPort", "error", err, "value", parts[orPortIdx])
			}
			// Parse DirPort (track errors for SEC-014)
			if _, err := fmt.Sscanf(parts[dirPortIdx], "%d", &currentRelay.DirPort); err != nil {
				portParseErrors++
				c.logger.Debug("Failed to parse DirPort", "error", err, "value", parts[dirPortIdx])
			}
		}

		// 解析 "a" 行。现行 dir-spec：附加 OR 地址（几乎总是 IPv6）。
		// 仍兼容极旧的 "a sha256=digest"（digest 现已在 m 行）。
		if strings.HasPrefix(line, "a ") && currentRelay != nil {
			applyALine(currentRelay, line)
		}

		// Parse "m" lines (microdescriptor digests) - SPEC-001 (consensus-method 33)
		// Modern format per dir-spec.txt §3.4.1: "m" SP 32*Base64Character
		// This is used in microdescriptor consensus (consensus-method 33+)
		if strings.HasPrefix(line, "m ") && currentRelay != nil {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentRelay.MicrodescDigest = parts[1]
			}
		}

		// Parse "s" lines (flags)
		if strings.HasPrefix(line, "s ") && currentRelay != nil {
			flags := strings.Fields(line[2:]) // Skip "s "
			currentRelay.Flags = flags
		}

		// Parse "w" lines (bandwidth weights) - path-spec.txt §2.2
		// Format: "w Bandwidth=12345" where value is in bytes/second
		if strings.HasPrefix(line, "w ") && currentRelay != nil {
			parts := strings.Fields(line[2:]) // Skip "w "
			for _, part := range parts {
				if strings.HasPrefix(part, "Bandwidth=") {
					bwStr := strings.TrimPrefix(part, "Bandwidth=")
					var bw uint64
					if _, err := fmt.Sscanf(bwStr, "%d", &bw); err == nil {
						currentRelay.Bandwidth = bw
						c.logger.Debug("Parsed bandwidth", "relay", currentRelay.Nickname, "bandwidth", currentRelay.Bandwidth)
					}
					break
				}
			}
		}

		// Parse "pr" lines (subprotocol versions) — Relay=4 表示 ntor-v3，FlowCtrl=2 表示拥塞控制。
		if strings.HasPrefix(line, "pr ") && currentRelay != nil {
			currentRelay.Protocols = ParseProtoLine(line)
		}

		// Parse "p" / "p6" 摘要。microdesc 共识通常把策略放在 microdescriptor。
		if currentRelay != nil && (strings.HasPrefix(line, "p ") || strings.HasPrefix(line, "p6 ")) {
			if pol, err := ParseExitPolicySummary(line); err == nil {
				if strings.HasPrefix(line, "p6 ") {
					currentRelay.ExitPolicyIPv6 = pol
				} else {
					currentRelay.ExitPolicy = pol
				}
			} else {
				c.logger.Debug("Failed to parse exit policy summary", "error", err, "line", line)
			}
		}
	}

	// Save last signature if any
	if currentSignature != nil {
		currentSignature.Signature = strings.Join(signatureLines, "\n")
		metadata.Signatures = append(metadata.Signatures, currentSignature)
	}

	// Add the last relay
	if currentRelay != nil {
		relays = append(relays, currentRelay)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading consensus: %w", err)
	}

	// Validate that consensus is not excessively malformed (SEC-004)
	// Reject if malformed entries exceed threshold, indicating possible attack or corruption
	malformedThreshold := totalEntries * maxMalformedEntryRate / 100
	if totalEntries > 0 && malformedEntries > malformedThreshold {
		c.logger.Warn("Excessive malformed entries in consensus",
			"malformed", malformedEntries, "total", totalEntries)
		return nil, nil, fmt.Errorf("excessive malformed entries in consensus: %d/%d (>%d%%)",
			malformedEntries, totalEntries, maxMalformedEntryRate)
	}

	// Warn if excessive port parse errors (SEC-014)
	portErrorThreshold := totalEntries * maxPortParseErrorRate / 100
	if totalEntries > 0 && portParseErrors > portErrorThreshold {
		c.logger.Warn("Excessive port parse errors in consensus",
			"port_errors", portParseErrors, "total", totalEntries)
	}

	if malformedEntries > 0 || portParseErrors > 0 {
		c.logger.Debug("Consensus parsing completed with some errors",
			"malformed", malformedEntries, "port_errors", portParseErrors,
			"total", totalEntries, "valid", len(relays))
	}

	// SPEC-003: Count authorities mentioned in consensus
	// This is a simple count based on number of signatures
	// In a full implementation, we would parse the entire authority section
	metadata.AuthorityCount = metadata.SignatureCount

	c.logger.Debug("Parsed consensus metadata",
		"signatures", metadata.SignatureCount,
		"valid_after", metadata.ValidAfter,
		"valid_until", metadata.ValidUntil)

	return relays, metadata, nil
}

// parseConsensusParams parses consensus network parameters from a "params" line
// Format: "key1=value1 key2=value2 ..." per dir-spec.txt §3.4.1
func parseConsensusParams(paramsStr string, params map[string]int) {
	for _, param := range strings.Fields(paramsStr) {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			var value int
			if _, err := fmt.Sscanf(parts[1], "%d", &value); err == nil {
				params[key] = value
			}
		}
	}
}

// parseSharedRandValueLine 解析 shared-rand-current/previous-value。
// 格式：shared-rand-*-value NumReveals Base64Value
func parseSharedRandValueLine(line string) []byte {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(raw) != 32 {
		// 兼容无 padding
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(fields[2], "="))
		if err != nil || len(raw) != 32 {
			return nil
		}
	}
	return raw
}

// HasFlag checks if a relay has a specific flag
func (r *Relay) HasFlag(flag string) bool {
	for _, f := range r.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

// IsGuard returns true if the relay is a guard
func (r *Relay) IsGuard() bool {
	return r.HasFlag("Guard")
}

// IsExit returns true if the relay is an exit
func (r *Relay) IsExit() bool {
	return r.HasFlag("Exit")
}

// IsStable returns true if the relay is stable
func (r *Relay) IsStable() bool {
	return r.HasFlag("Stable")
}

// IsRunning returns true if the relay is running
func (r *Relay) IsRunning() bool {
	return r.HasFlag("Running")
}

// IsValid returns true if the relay is valid
func (r *Relay) IsValid() bool {
	return r.HasFlag("Valid")
}

// IsFast 非测试电路的每一跳都必须有 Fast（path-spec universal constraints）。
func (r *Relay) IsFast() bool {
	return r != nil && r.HasFlag("Fast")
}

// IsMiddleOnly 只能当 middle：不得做 Guard / Exit（proposal 334）。
func (r *Relay) IsMiddleOnly() bool {
	return r != nil && r.HasFlag("MiddleOnly")
}

// IsBadExit 不得选为出口（除非用户显式要求；本客户端无该覆盖）。
func (r *Relay) IsBadExit() bool {
	return r != nil && r.HasFlag("BadExit")
}

// UsableAsCircuitHop 最新 Tor 非测试电路的每一跳：Running + Valid + Fast。
func (r *Relay) UsableAsCircuitHop() bool {
	return r != nil && r.IsRunning() && r.IsValid() && r.IsFast()
}

// UsableAsGuard Guard 位另需 Guard + Stable，且不得 MiddleOnly。
func (r *Relay) UsableAsGuard() bool {
	return r.UsableAsCircuitHop() && r.IsGuard() && r.IsStable() && !r.IsMiddleOnly()
}

// UsableAsExit Exit 位不得 MiddleOnly / BadExit。端口策略另由 AllowsExitTarget 判断。
func (r *Relay) UsableAsExit() bool {
	return r.UsableAsCircuitHop() && !r.IsMiddleOnly() && !r.IsBadExit()
}

// String returns a string representation of the relay
func (r *Relay) String() string {
	return fmt.Sprintf("%s (%s:%d)", r.Nickname, r.Address, r.ORPort)
}

// RSAIdentityBytes 返回 ntor NODEID（20 字节 RSA fingerprint）。
func (r *Relay) RSAIdentityBytes() []byte {
	return r.RSAIdentity
}

// GetFingerprintHex 返回 40 字符大写 hex fingerprint。
func (r *Relay) GetFingerprintHex() string {
	if r.FingerprintHex != "" {
		return r.FingerprintHex
	}
	if len(r.RSAIdentity) == 20 {
		return fingerprintHex(r.RSAIdentity)
	}
	return r.Fingerprint
}

// GetIdentityKey returns the relay's Ed25519 identity key (SPEC-001)
func (r *Relay) GetIdentityKey() []byte {
	return r.IdentityKey
}

// GetNtorOnionKey returns the relay's Curve25519 ntor onion key (SPEC-001)
func (r *Relay) GetNtorOnionKey() []byte {
	return r.NtorOnionKey
}

// HasNtorKeys 表示 CREATE2 所需的 RSA NODEID + ntor onion key 已齐。
func (r *Relay) HasNtorKeys() bool {
	return len(r.RSAIdentity) == 20 && len(r.NtorOnionKey) == 32 && !allZero(r.RSAIdentity) && !allZero(r.NtorOnionKey)
}

// HasExtendKeys 表示 EXTEND2 还需要 Ed25519 identity。
func (r *Relay) HasExtendKeys() bool {
	return r.HasNtorKeys() && len(r.IdentityKey) == 32 && !allZero(r.IdentityKey)
}

// HasValidKeys 保持旧名，要求完整 3-hop 密钥。
func (r *Relay) HasValidKeys() bool {
	return r.HasExtendKeys()
}

func allZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

// InSameSubnet checks if this relay shares a /16 subnet with another relay
// This is a heuristic for detecting relays operated by the same entity
// per path-spec.txt §2.2.1 "Do not use the same /16 subnet"
func (r *Relay) InSameSubnet(other *Relay) bool {
	return getSubnet16(r.Address) == getSubnet16(other.Address)
}

// getSubnet16 extracts the /16 subnet from an IP address
func getSubnet16(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return address
}

// SPEC-003: Enhanced consensus validation infrastructure
// These types and methods provide hooks for implementing full multi-signature
// threshold validation per dir-spec.txt section 3.4

// ConsensusSignature represents a directory authority signature (SPEC-003)
type ConsensusSignature struct {
	Algorithm        string // Signature algorithm (e.g., "sha256")
	Identity         string // Authority identity key digest
	SigningKeyDigest string // Signing key digest
	Signature        string // Base64-encoded signature block
}

// ConsensusMetadata contains metadata about a consensus document (SPEC-003)
type ConsensusMetadata struct {
	ValidAfter           time.Time
	FreshUntil           time.Time
	ValidUntil           time.Time
	Signatures           []*ConsensusSignature // Parsed authority signatures
	SignatureCount       int                   // Number of authority signatures
	AuthorityCount       int                   // Number of authorities in consensus
	NetworkStatusVersion int                   // Consensus format version
	Params               map[string]int        // Network-wide consensus parameters (dir-spec.txt §3.4.1)
	SharedRandCurrent    []byte                // shared-rand-current-value（32 字节，可空）
	SharedRandPrevious   []byte                // shared-rand-previous-value（32 字节，可空）
}

// ValidateConsensusMetadata 校验时间窗与签名个数。密码学验签在
// Client.VerifyConsensusSignatures，并由 FetchConsensus 强制调用。
func ValidateConsensusMetadata(meta *ConsensusMetadata) error {
	now := time.Now()

	// Validate timestamps are present
	if meta.ValidAfter.IsZero() || meta.ValidUntil.IsZero() {
		return fmt.Errorf("consensus missing required timestamp fields")
	}

	// Check clock skew
	if meta.ValidAfter.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("consensus valid-after time is too far in the future")
	}

	// Check expiration
	if meta.ValidUntil.Before(now.Add(-maxClockSkew)) {
		return fmt.Errorf("consensus has expired")
	}

	// Validate signature count meets minimum threshold
	// Per dir-spec.txt §3.4, a valid consensus requires signatures from a quorum of authorities
	if meta.SignatureCount < minSignatureThreshold {
		return fmt.Errorf("insufficient signatures: %d < %d", meta.SignatureCount, minSignatureThreshold)
	}

	// Authority count validation
	if meta.AuthorityCount < minDirectoryAuthorities {
		return fmt.Errorf("insufficient authorities: %d < %d", meta.AuthorityCount, minDirectoryAuthorities)
	}

	// Validate we actually parsed signature structures
	if len(meta.Signatures) != meta.SignatureCount {
		return fmt.Errorf("signature count mismatch: parsed %d but counted %d", len(meta.Signatures), meta.SignatureCount)
	}

	// Validate each signature has required fields
	for i, sig := range meta.Signatures {
		if sig.Algorithm == "" || sig.Identity == "" || sig.Signature == "" {
			return fmt.Errorf("signature %d missing required fields", i)
		}
	}

	return nil
}

// PaddingParams contains circuit padding parameters from consensus
// These parameters control padding machine behavior network-wide
type PaddingParams struct {
	// Global padding settings
	GlobalAllowedCells int  // Maximum padding cells allowed globally
	PaddingDisabled    bool // Whether padding is disabled network-wide

	// APE (Adaptive Padding Engine) parameters
	APEBurstMin    int // Minimum cells in a burst (default: 2)
	APEBurstMax    int // Maximum cells in a burst (default: 10)
	APEGapMinMS    int // Minimum gap between bursts in milliseconds (default: 1500)
	APEGapMaxMS    int // Maximum gap between bursts in milliseconds (default: 9500)
	APECellDelayMS int // Delay between cells in a burst in milliseconds (default: 20)

	// Circuit setup padding parameters
	SetupBurstMin    int // Minimum cells in setup burst (default: 1)
	SetupBurstMax    int // Maximum cells in setup burst (default: 5)
	SetupGapMinMS    int // Minimum setup gap in milliseconds (default: 500)
	SetupGapMaxMS    int // Maximum setup gap in milliseconds (default: 2000)
	SetupCellDelayMS int // Setup cell delay in milliseconds (default: 50)
}

// GetPaddingParams extracts padding-related parameters from consensus metadata
// Returns parameters with spec-compliant defaults if not present in consensus
func GetPaddingParams(meta *ConsensusMetadata) *PaddingParams {
	params := &PaddingParams{
		// Defaults from padding-spec.txt §3 and implementation experience
		GlobalAllowedCells: 0, // 0 means unlimited
		PaddingDisabled:    false,
		APEBurstMin:        2,
		APEBurstMax:        10,
		APEGapMinMS:        1500,
		APEGapMaxMS:        9500,
		APECellDelayMS:     20,
		SetupBurstMin:      1,
		SetupBurstMax:      5,
		SetupGapMinMS:      500,
		SetupGapMaxMS:      2000,
		SetupCellDelayMS:   50,
	}

	if meta == nil || meta.Params == nil {
		return params
	}

	// Parse global padding parameters
	if val, ok := meta.Params["circpad_global_allowed_cells"]; ok {
		params.GlobalAllowedCells = val
	}
	if val, ok := meta.Params["circpad_padding_disabled"]; ok {
		params.PaddingDisabled = val != 0
	}

	// Parse APE parameters (using nf_* prefix for network flow obfuscation)
	if val, ok := meta.Params["nf_ito_low"]; ok && val > 0 {
		params.APEGapMinMS = val
	}
	if val, ok := meta.Params["nf_ito_high"]; ok && val > 0 {
		params.APEGapMaxMS = val
	}
	if val, ok := meta.Params["circpad_ape_burst_min"]; ok && val > 0 {
		params.APEBurstMin = val
	}
	if val, ok := meta.Params["circpad_ape_burst_max"]; ok && val > 0 {
		params.APEBurstMax = val
	}
	if val, ok := meta.Params["circpad_ape_cell_delay"]; ok && val > 0 {
		params.APECellDelayMS = val
	}

	// Parse circuit setup padding parameters
	if val, ok := meta.Params["circpad_setup_burst_min"]; ok && val > 0 {
		params.SetupBurstMin = val
	}
	if val, ok := meta.Params["circpad_setup_burst_max"]; ok && val > 0 {
		params.SetupBurstMax = val
	}
	if val, ok := meta.Params["circpad_setup_gap_min"]; ok && val > 0 {
		params.SetupGapMinMS = val
	}
	if val, ok := meta.Params["circpad_setup_gap_max"]; ok && val > 0 {
		params.SetupGapMaxMS = val
	}
	if val, ok := meta.Params["circpad_setup_cell_delay"]; ok && val > 0 {
		params.SetupCellDelayMS = val
	}

	return params
}

// isKnownAuthority checks if a v3ident fingerprint belongs to a known directory authority (SPEC-003)
func isKnownAuthority(v3ident string) bool {
	v3identUpper := strings.ToUpper(v3ident)
	for _, auth := range KnownAuthorities {
		if auth.V3Ident == v3identUpper {
			return true
		}
	}
	return false
}

// getAuthorityName returns the nickname of a directory authority by v3ident (SPEC-003)
func getAuthorityName(v3ident string) string {
	v3identUpper := strings.ToUpper(v3ident)
	for _, auth := range KnownAuthorities {
		if auth.V3Ident == v3identUpper {
			return auth.Nickname
		}
	}
	return "unknown"
}

// Get 按 identity 取权威证书；生产验签应走 getMatching 以绑定 signing-key-digest。
func (c *AuthorityCertCache) Get(ctx context.Context, identity string, httpClient *http.Client, authorities []string) (*AuthorityCert, error) {
	return c.getMatching(ctx, identity, "", httpClient, authorities)
}

func (c *AuthorityCertCache) getMatching(ctx context.Context, identity, signingDigest string, httpClient *http.Client, authorities []string) (*AuthorityCert, error) {
	identity = strings.ToUpper(identity)
	signingDigest = strings.ToUpper(signingDigest)

	c.mu.RLock()
	cert, ok := c.certs[identity]
	c.mu.RUnlock()
	if ok && cacheFresh(cert) && signingKeyMatches(cert, signingDigest) {
		return cert, nil
	}

	// HTTP 不能占写锁，否则并行预取会被串行化
	newCert, err := c.fetchAuthorityCert(ctx, identity, signingDigest, httpClient, authorities)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authority certificate: %w", err)
	}

	c.mu.Lock()
	if existing, ok := c.certs[identity]; ok && cacheFresh(existing) && signingKeyMatches(existing, signingDigest) {
		c.mu.Unlock()
		return existing, nil
	}
	c.certs[identity] = newCert
	c.mu.Unlock()
	c.persistToDisk()
	c.logger.Info("Cached authority certificate", "identity", identity, "expires", newCert.ExpiresAt)
	return newCert, nil
}

func cacheFresh(cert *AuthorityCert) bool {
	if cert == nil {
		return false
	}
	// 可用性以 dir-key-expires 为准（C Tor cached-certs）。加载时仍强制
	// certification / crosscert；过期证书不得使用。
	return time.Now().Before(cert.ExpiresAt)
}

// fetchAuthorityCert 从 /tor/keys/fp/<IDENTITY> 拉取证书，并校验 certification / crosscert。
func (c *AuthorityCertCache) fetchAuthorityCert(ctx context.Context, identity, signingDigest string, httpClient *http.Client, authorities []string) (*AuthorityCert, error) {
	if len(authorities) == 0 {
		return nil, fmt.Errorf("no directory authorities configured")
	}

	var lastErr error
	for _, authority := range authorities {
		baseURL := strings.TrimSuffix(authority, "/tor/status-vote/current/consensus-microdesc")
		baseURL = strings.TrimSuffix(baseURL, "/tor/status-vote/current/consensus")
		baseURL = strings.TrimRight(baseURL, "/")
		certURL := baseURL + "/tor/keys/fp/" + strings.ToUpper(identity)

		req, err := http.NewRequestWithContext(ctx, "GET", certURL, nil)
		if err != nil {
			lastErr = err
			continue
		}

		c.keyFetches.Add(1)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxCachedCertsBytes+1))
		_ = resp.Body.Close()

		if err != nil {
			lastErr = err
			continue
		}
		if len(body) > maxCachedCertsBytes {
			lastErr = fmt.Errorf("authority certificate exceeds %d bytes", maxCachedCertsBytes)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status: %d", resp.StatusCode)
			continue
		}

		cert, err := c.parseAuthorityCertMatching(body, identity, signingDigest)
		if err != nil {
			lastErr = err
			continue
		}

		return cert, nil
	}

	return nil, fmt.Errorf("failed to fetch from any authority: %w", lastErr)
}

func (c *AuthorityCertCache) parseAuthorityCert(data []byte, expectedIdentity string) (*AuthorityCert, error) {
	return c.parseAuthorityCertMatching(data, expectedIdentity, "")
}

func (c *AuthorityCertCache) parseAuthorityCertMatching(data []byte, expectedIdentity, signingDigest string) (*AuthorityCert, error) {
	cert, err := parseAndSelectAuthorityCert(data, expectedIdentity, signingDigest)
	if err != nil {
		return nil, err
	}
	cert.FetchedAt = time.Now()
	return cert, nil
}

// VerifyConsensusSignatures 用硬编码 KnownAuthorities 的 identity 证书校验共识签名。
//
// consensusBody 必须是 extractConsensusSignedBody 的结果（到 directory-signature 后的空格）。
// 每条签名还要求：
//  1. identity ∈ KnownAuthorities
//  2. SHA1(PKCS1(identity key)) == v3ident
//  3. dir-key-certification / dir-key-crosscert 通过
//  4. SHA1(PKCS1(signing key)) == directory-signature 的 signing-key-digest
//  5. PKCS#1（不含 algorithmIdentifier）对 signed body 的 sha256/sha1 验签通过
func (c *Client) VerifyConsensusSignatures(ctx context.Context, consensusBody []byte, meta *ConsensusMetadata) error {
	if len(consensusBody) == 0 {
		return fmt.Errorf("empty consensus body")
	}

	if meta == nil || len(meta.Signatures) == 0 {
		return fmt.Errorf("no signatures to verify")
	}

	validIdentities := make(map[string]struct{})

	for _, sig := range meta.Signatures {
		identity := strings.ToUpper(sig.Identity)
		if !isKnownAuthority(identity) {
			c.logger.Debug("Unknown authority", "identity", identity)
			continue
		}

		sigBytes, err := decodeSignatureBlock(sig.Signature)
		if err != nil {
			c.logger.Debug("Failed to decode signature", "identity", identity, "error", err)
			continue
		}
		if len(sigBytes) < 128 {
			c.logger.Debug("Signature too short", "identity", identity, "length", len(sigBytes))
			continue
		}

		cert, err := c.certCache.getMatching(ctx, identity, sig.SigningKeyDigest, c.httpClient, c.authorities)
		if err != nil {
			c.logger.Warn("Failed to get authority certificate", "identity", identity, "error", err)
			continue
		}

		signingDigest := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(cert.SigningKey)))
		if sig.SigningKeyDigest != "" && signingDigest != strings.ToUpper(sig.SigningKeyDigest) {
			c.logger.Debug("Signing key digest mismatch", "identity", identity, "got", signingDigest, "want", sig.SigningKeyDigest)
			continue
		}

		var hash []byte
		switch strings.ToLower(sig.Algorithm) {
		case "sha256":
			h := sha256.Sum256(consensusBody)
			hash = h[:]
		case "sha1", "":
			h := sha1.Sum(consensusBody)
			hash = h[:]
		default:
			c.logger.Debug("Unknown signature algorithm", "algorithm", sig.Algorithm)
			continue
		}

		if err := rsa.VerifyPKCS1v15(cert.SigningKey, 0, hash, sigBytes); err != nil {
			c.logger.Debug("RSA signature verification failed", "identity", identity, "error", err)
			continue
		}

		c.logger.Debug("Valid signature verified", "identity", identity, "authority", getAuthorityName(identity))
		validIdentities[identity] = struct{}{}
	}

	if len(validIdentities) < minDirectoryAuthorities {
		return fmt.Errorf("insufficient known authorities: %d < %d", len(validIdentities), minDirectoryAuthorities)
	}
	if len(validIdentities) < minSignatureThreshold {
		return fmt.Errorf("insufficient valid signatures: %d < %d (verified %d total)", len(validIdentities), minSignatureThreshold, len(meta.Signatures))
	}

	c.logger.Info("Consensus signatures verified", "valid", len(validIdentities), "authorities", len(validIdentities))
	return nil
}

// prefetchAuthorityCerts 并行拉取签名里出现的已知权威证书，避免验签阶段串行 HTTP。
func (c *Client) prefetchAuthorityCerts(ctx context.Context, meta *ConsensusMetadata) {
	if meta == nil {
		return
	}
	type job struct {
		identity, digest string
	}
	seen := make(map[string]struct{})
	var jobs []job
	for _, sig := range meta.Signatures {
		identity := strings.ToUpper(sig.Identity)
		if !isKnownAuthority(identity) {
			continue
		}
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		jobs = append(jobs, job{identity: identity, digest: sig.SigningKeyDigest})
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			_, _ = c.certCache.getMatching(ctx, j.identity, j.digest, c.httpClient, c.authorities)
		}(j)
	}
	wg.Wait()
}

func decodeSignatureBlock(sigBlock string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(sigBlock)); block != nil && len(block.Bytes) > 0 {
		return block.Bytes, nil
	}
	sigData := extractSignatureData(sigBlock)
	if sigData == "" {
		sigData = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, sigBlock)
	}
	if sigData == "" {
		return nil, fmt.Errorf("missing signature PEM")
	}
	wrapped := "-----BEGIN SIGNATURE-----\n" + sigData + "\n-----END SIGNATURE-----\n"
	block, _ := pem.Decode([]byte(wrapped))
	if block == nil || len(block.Bytes) == 0 {
		return nil, fmt.Errorf("invalid signature encoding")
	}
	return block.Bytes, nil
}

// extractSignatureData extracts base64 signature data from PEM-style signature block
func extractSignatureData(sigBlock string) string {
	lines := strings.Split(sigBlock, "\n")
	var sigData strings.Builder

	inBlock := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(line, "-----END") {
			break
		}
		if inBlock && line != "" {
			sigData.WriteString(line)
		}
	}

	return sigData.String()
}
