package relay

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/onion"
)

const (
	maxHSDirEntries = 64
	maxHSDirBody    = 100 << 10
	hsDirTTL        = 3 * time.Hour
)

type hsDirEntry struct {
	body []byte
	mod  time.Time
}

// hsDirStore 内存保存已 POST 的 v3 外层描述符。未宣告 HSDir=2。
type hsDirStore struct {
	mu      sync.Mutex
	entries []hsDirEntry
}

func (s *hsDirStore) put(body []byte) bool {
	if s == nil || len(body) == 0 || len(body) > maxHSDirBody {
		return false
	}
	if !strings.HasPrefix(string(body), "hs-descriptor") {
		return false
	}
	desc, err := onion.ParseDescriptor(body)
	if err != nil || desc == nil || len(desc.DescriptorSigningKeyCert) == 0 {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	if len(s.entries) >= maxHSDirEntries {
		s.entries = s.entries[1:]
	}
	s.entries = append(s.entries, hsDirEntry{body: append([]byte(nil), body...), mod: now})
	return true
}

func (s *hsDirStore) get(blinded []byte) ([]byte, time.Time, bool) {
	if s == nil || len(blinded) != 32 {
		return nil, time.Time{}, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := s.entries[i]
		if onion.MatchHSDirDescriptor(e.body, blinded) {
			return e.body, e.mod, true
		}
	}
	return nil, time.Time{}, false
}

func (s *hsDirStore) expireLocked(now time.Time) {
	kept := s.entries[:0]
	for _, e := range s.entries {
		if now.Sub(e.mod) < hsDirTTL {
			kept = append(kept, e)
		}
	}
	s.entries = kept
}

func (d *DirCacheServer) serveHSPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHSDirBody+1))
	if err != nil || len(body) == 0 || len(body) > maxHSDirBody {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if d.hs == nil || !d.hs.put(body) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (d *DirCacheServer) serveHSFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/tor/hs/3/")
	raw = strings.Trim(raw, "/")
	if raw == "" || raw == "publish" {
		http.NotFound(w, r)
		return
	}
	blinded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(blinded) != 32 {
		http.NotFound(w, r)
		return
	}
	body, mod, ok := d.hs.get(blinded)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeDirBody(w, r, body, mod)
}
