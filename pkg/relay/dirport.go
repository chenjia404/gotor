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
