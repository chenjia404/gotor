package relay

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

const maxDirServeBytes = 8 << 20

// DirCacheServer 用 CacheDirectory 的落盘共识/microdesc 应答 BEGIN_DIR / DirPort。
type DirCacheServer struct {
	cacheDir string
	logger   *logger.Logger
	srv      *http.Server
	ln       net.Listener
}

func NewDirCacheServer(cacheDir string, log *logger.Logger) *DirCacheServer {
	if log == nil {
		log = logger.NewDefault()
	}
	return &DirCacheServer{cacheDir: cacheDir, logger: log.Component("dircache")}
}

func (d *DirCacheServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus-microdesc", d.serveFile("cached-microdesc-consensus"))
	mux.HandleFunc("/tor/status-vote/current/consensus", d.serveFile("cached-microdesc-consensus"))
	mux.HandleFunc("/tor/micro/all", d.serveFile("cached-microdescs"))
	mux.HandleFunc("/tor/keys/all", d.serveFile("cached-certs"))
	mux.HandleFunc("/tor/keys/fp/", d.serveKeysFP)
	return mux
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
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.CopyN(w, f, st.Size())
	}
}

const (
	maxKeyFPQuery     = 16
	authCertFPHexLen  = 40
	maxCachedCertsLen = 2 << 20
)

// serveKeysFP 按 dir-spec 提供 /tor/keys/fp/<F>[+<F>…]，从 CacheDirectory/cached-certs 抽取。
// 未实现 consdiff；本切片不宣告 DirCache=2。
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
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
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
