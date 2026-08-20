package relay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

type dirZKey struct{}

const maxDirServeBytes = 8 << 20

const (
	cachedConsensusName     = "cached-microdesc-consensus"
	cachedConsensusPrevName = "cached-microdesc-consensus.prev"
)

// DirCacheServer 用 CacheDirectory 的落盘共识/microdesc 应答 BEGIN_DIR / DirPort。
// 可按 X-Or-Diff-From-Consensus 或 /diff/<HASH>/ 提供 limited-ed，并协商 gzip/deflate/.z 与 304；不宣告 DirCache=2。
type DirCacheServer struct {
	cacheDir string
	logger   *logger.Logger
	srv      *http.Server
	ln       net.Listener

	diffMu     sync.Mutex
	diffFrom   string
	diffTo     string
	diffCached string

	hs *hsDirStore
}

func NewDirCacheServer(cacheDir string, log *logger.Logger) *DirCacheServer {
	if log == nil {
		log = logger.NewDefault()
	}
	return &DirCacheServer{cacheDir: cacheDir, logger: log.Component("dircache"), hs: &hsDirStore{}}
}

func (d *DirCacheServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus-microdesc/diff/", d.serveConsensusDiffPath)
	mux.HandleFunc("/tor/status-vote/current/consensus/diff/", d.serveConsensusDiffPath)
	mux.HandleFunc("/tor/status-vote/current/consensus-microdesc", d.serveConsensus)
	mux.HandleFunc("/tor/status-vote/current/consensus", d.serveConsensus)
	mux.HandleFunc("/tor/micro/all", d.serveFile("cached-microdescs"))
	mux.HandleFunc("/tor/keys/all", d.serveFile("cached-certs"))
	mux.HandleFunc("/tor/keys/fp/", d.serveKeysFP)
	mux.HandleFunc("/tor/hs/3/publish", d.serveHSPublish)
	mux.HandleFunc("/tor/hs/3/", d.serveHSFetch)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".z") {
			clone := r.Clone(context.WithValue(r.Context(), dirZKey{}, true))
			u := *r.URL
			u.Path = strings.TrimSuffix(r.URL.Path, ".z")
			clone.URL = &u
			mux.ServeHTTP(w, clone)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (d *DirCacheServer) serveFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if d.cacheDir == "" {
			http.NotFound(w, r)
			return
		}
		base := filepath.Clean(d.cacheDir)
		path := filepath.Join(base, name)
		if !strings.HasPrefix(path, base+string(os.PathSeparator)) && path != base {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(path) // #nosec G304 -- 仅允许 CacheDirectory 固定文件名
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil || st.Size() <= 0 || st.Size() > maxDirServeBytes {
			http.NotFound(w, r)
			return
		}
		data := make([]byte, st.Size())
		if _, err := io.ReadFull(f, data); err != nil {
			http.NotFound(w, r)
			return
		}
		writeDirBody(w, r, data, st.ModTime())
	}
}

const (
	maxKeyFPQuery     = 16
	authCertFPHexLen  = 40
	maxCachedCertsLen = 2 << 20
)

func (d *DirCacheServer) serveConsensus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	curr, ok := d.readCachedFile(cachedConsensusName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	hashes := directory.ParseOrDiffFromConsensusHeader(r.Header.Get("X-Or-Diff-From-Consensus"))
	mod := consensusLastModified(curr, d.cachedModTime(cachedConsensusName))
	if len(hashes) > 0 {
		if diff, ok := d.diffFromHashes(hashes, curr); ok {
			writeDirBody(w, r, []byte(diff), mod)
			return
		}
	}
	writeDirBody(w, r, []byte(curr), mod)
}

func (d *DirCacheServer) serveConsensusDiffPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hash, ok := parseConsensusDiffPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	curr, ok := d.readCachedFile(cachedConsensusName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	diff, ok := d.diffFromHashes([]string{hash}, curr)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeDirBody(w, r, []byte(diff), consensusLastModified(curr, d.cachedModTime(cachedConsensusName)))
}

func parseConsensusDiffPath(path string) (hash string, ok bool) {
	const (
		micro = "/tor/status-vote/current/consensus-microdesc/diff/"
		ns    = "/tor/status-vote/current/consensus/diff/"
	)
	rest := ""
	switch {
	case strings.HasPrefix(path, micro):
		rest = strings.TrimPrefix(path, micro)
	case strings.HasPrefix(path, ns):
		rest = strings.TrimPrefix(path, ns)
	default:
		return "", false
	}
	rest = strings.Trim(rest, "/")
	if rest == "" || strings.Contains(rest, "..") {
		return "", false
	}
	hash, _, _ = strings.Cut(rest, "/")
	hash = strings.ToLower(hash)
	if len(hash) != 64 {
		return "", false
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return hash, true
}

func (d *DirCacheServer) diffFromHashes(hashes []string, curr string) (string, bool) {
	prev, ok := d.readCachedFile(cachedConsensusPrevName)
	if !ok {
		return "", false
	}
	from := strings.ToLower(directory.ConsensusDiffFromDigest(prev))
	to := strings.ToLower(directory.ConsensusDiffFromDigest(curr))
	matched := false
	for _, h := range hashes {
		if strings.EqualFold(h, from) {
			matched = true
			break
		}
	}
	if !matched {
		return "", false
	}

	d.diffMu.Lock()
	defer d.diffMu.Unlock()
	if d.diffCached != "" && d.diffFrom == from && d.diffTo == to {
		return d.diffCached, true
	}
	diff, err := directory.GenerateConsensusDiff(prev, curr)
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("consdiff generate failed; serving full consensus instead", "error", err)
		}
		return "", false
	}
	d.diffFrom = from
	d.diffTo = to
	d.diffCached = diff
	return diff, true
}

func (d *DirCacheServer) readCachedFile(name string) (string, bool) {
	if d.cacheDir == "" {
		return "", false
	}
	base := filepath.Clean(d.cacheDir)
	path := filepath.Join(base, name)
	if !strings.HasPrefix(path, base+string(os.PathSeparator)) && path != base {
		return "", false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- 仅允许 CacheDirectory 固定文件名
	if err != nil || len(data) == 0 || len(data) > maxDirServeBytes {
		return "", false
	}
	return string(data), true
}

func (d *DirCacheServer) cachedModTime(name string) time.Time {
	if d.cacheDir == "" {
		return time.Time{}
	}
	st, err := os.Stat(filepath.Join(d.cacheDir, name))
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func consensusLastModified(doc string, fallback time.Time) time.Time {
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "valid-after ") {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(line[len("valid-after "):]), time.UTC)
		if err == nil {
			return t
		}
		break
	}
	return fallback
}

func writeDirBody(w http.ResponseWriter, r *http.Request, body []byte, mod time.Time) {
	if !mod.IsZero() {
		lm := mod.UTC().Truncate(time.Second)
		w.Header().Set("Last-Modified", lm.Format(http.TimeFormat))
		if ims := r.Header.Get("If-Modified-Since"); ims != "" {
			if t, err := http.ParseTime(ims); err == nil && !lm.After(t.UTC().Truncate(time.Second)) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	enc, hideCE := negotiateDirEncoding(r)
	payload, used := compressDirBody(enc, body)
	if used != "" && !hideCE {
		w.Header().Set("Content-Encoding", used)
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	if r.Method == http.MethodHead {
		return
	}
	writeDirPayload(w, payload)
}

// writeDirPayload 写出已落盘的目录文档（或失败时的未压缩原文）。
// Content-Type 固定 text/plain；不是 HTML，gosec G705 的 XSS 污点在此不适用。
func writeDirPayload(w http.ResponseWriter, payload []byte) {
	_, _ = w.Write(payload) // #nosec G705 -- 目录文档来自 CacheDirectory，非请求体反射
}

func acceptEncodingTokens(h string) []string {
	if h == "" {
		return nil
	}
	parts := strings.Split(h, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p, _, _ = strings.Cut(p, ";")
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasAcceptToken(toks []string, name string) bool {
	for _, t := range toks {
		if t == name {
			return true
		}
	}
	return false
}

func negotiateDirEncoding(r *http.Request) (enc string, hideCE bool) {
	_, isZ := r.Context().Value(dirZKey{}).(bool)
	raw := r.Header.Get("Accept-Encoding")
	if raw == "" {
		if isZ {
			return "deflate", true
		}
		return "", false
	}
	toks := acceptEncodingTokens(raw)
	if hasAcceptToken(toks, "gzip") {
		return "gzip", false
	}
	if hasAcceptToken(toks, "deflate") {
		return "deflate", false
	}
	return "", false
}

func compressDirBody(enc string, body []byte) (payload []byte, used string) {
	switch enc {
	case "gzip":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return body, ""
		}
		if err := zw.Close(); err != nil {
			return body, ""
		}
		return buf.Bytes(), "gzip"
	case "deflate":
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return body, ""
		}
		if err := zw.Close(); err != nil {
			return body, ""
		}
		return buf.Bytes(), "deflate"
	default:
		return body, ""
	}
}

// serveKeysFP 按 dir-spec 提供 /tor/keys/fp/<F>[+<F>…]，从 CacheDirectory/cached-certs 抽取。
// consdiff / gzip / 304 已接线；在缺多小时历史 diff / 真网被当缓存之前，禁止宣告 DirCache=2。
func (d *DirCacheServer) serveKeysFP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
	fps, ok := parseKeyFingerprints(raw)
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, found := d.lookupCachedCerts(fps)
	if !found {
		http.NotFound(w, r)
		return
	}
	writeDirBody(w, r, body, d.cachedModTime("cached-certs"))
}

func parseKeyFingerprints(raw string) ([]string, bool) {
	if raw == "" || len(raw) > maxKeyFPQuery*(authCertFPHexLen+1) {
		return nil, false
	}
	parts := strings.Split(raw, "+")
	if len(parts) == 0 || len(parts) > maxKeyFPQuery {
		return nil, false
	}
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		fp := strings.ToUpper(strings.ReplaceAll(p, " ", ""))
		if len(fp) != authCertFPHexLen || !isHexFingerprint(fp) {
			return nil, false
		}
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, fp)
	}
	return out, len(out) > 0
}

func isHexFingerprint(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func (d *DirCacheServer) lookupCachedCerts(fps []string) ([]byte, bool) {
	if d.cacheDir == "" {
		return nil, false
	}
	base := filepath.Clean(d.cacheDir)
	path := filepath.Join(base, "cached-certs")
	if !strings.HasPrefix(path, base+string(os.PathSeparator)) && path != base {
		return nil, false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- 仅允许 CacheDirectory/cached-certs
	if err != nil || len(data) == 0 || len(data) > maxCachedCertsLen {
		return nil, false
	}
	want := make(map[string]struct{}, len(fps))
	for _, fp := range fps {
		want[fp] = struct{}{}
	}
	var buf strings.Builder
	matched := 0
	for _, part := range splitDirKeyCertificates(string(data)) {
		fp := certFingerprintField(part)
		if _, ok := want[fp]; !ok {
			continue
		}
		buf.WriteString(part)
		if !strings.HasSuffix(part, "\n") {
			buf.WriteByte('\n')
		}
		matched++
	}
	if matched == 0 {
		return nil, false
	}
	return []byte(buf.String()), true
}

func splitDirKeyCertificates(document string) []string {
	const marker = "dir-key-certificate-version"
	var parts []string
	rest := document
	for {
		idx := strings.Index(rest, marker)
		if idx < 0 {
			break
		}
		rest = rest[idx:]
		next := strings.Index(rest[len(marker):], marker)
		if next < 0 {
			parts = append(parts, rest)
			break
		}
		cut := len(marker) + next
		parts = append(parts, rest[:cut])
		rest = rest[cut:]
	}
	return parts
}

func certFingerprintField(document string) string {
	for _, line := range strings.Split(document, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "fingerprint ") {
			continue
		}
		fp := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(line[len("fingerprint "):]), " ", ""))
		if len(fp) == authCertFPHexLen && isHexFingerprint(fp) {
			return fp
		}
	}
	return ""
}

// Listen 在 addr 上启动明文 DirPort（可选）。
func (d *DirCacheServer) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	d.ln = ln
	d.srv = &http.Server{
		Handler:           d.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 14,
	}
	go func() {
		_ = d.srv.Serve(ln)
	}()
	d.logger.Info("DirPort listening", "addr", addr)
	return nil
}

// Dial 返回一对连接到本机目录处理器的连接（BEGIN_DIR）。
func (d *DirCacheServer) Dial() (net.Conn, error) {
	client, server := net.Pipe()
	go d.servePipe(server)
	return client, nil
}

func (d *DirCacheServer) servePipe(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return
	}
	rw := &pipeResponse{conn: c, header: make(http.Header)}
	d.handler().ServeHTTP(rw, req)
	rw.finish()
}

func (d *DirCacheServer) Close() error {
	if d.srv != nil {
		_ = d.srv.Close()
	}
	if d.ln != nil {
		return d.ln.Close()
	}
	return nil
}

type pipeResponse struct {
	conn        net.Conn
	header      http.Header
	status      int
	wroteHeader bool
}

func (w *pipeResponse) Header() http.Header { return w.header }

func (w *pipeResponse) Write(p []byte) (int, error) {
	w.writeHeader(http.StatusOK)
	return w.conn.Write(p)
}

func (w *pipeResponse) WriteHeader(status int) { w.writeHeader(status) }

func (w *pipeResponse) writeHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if status == 0 {
		status = http.StatusOK
	}
	w.status = status
	fmt.Fprintf(w.conn, "HTTP/1.0 %d %s\r\n", status, http.StatusText(status))
	_ = w.header.Write(w.conn)
	_, _ = w.conn.Write([]byte("\r\n"))
}

func (w *pipeResponse) finish() {
	if !w.wroteHeader {
		w.writeHeader(http.StatusOK)
	}
}
