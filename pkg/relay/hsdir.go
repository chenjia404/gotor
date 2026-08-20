package relay

import (
	"encoding/base64"
	"encoding/hex"
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
	body     []byte
	mod      time.Time
	revision uint64
}

// hsDirStore 按盲化公钥保存已验签的 v3 外层描述符。未宣告 HSDir=2。
type hsDirStore struct {
	mu      sync.Mutex
	byBlind map[string]*hsDirEntry
}

func (s *hsDirStore) put(body []byte) bool {
	if s == nil || len(body) == 0 || len(body) > maxHSDirBody {
		return false
	}
	if !strings.HasPrefix(string(body), "hs-descriptor") {
		return false
	}
	blinded, revision, canonical, err := onion.VerifyHSDirOuterDescriptor(body)
	if err != nil || len(blinded) != 32 || len(canonical) == 0 {
		return false
	}
	key := hex.EncodeToString(blinded)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byBlind == nil {
		s.byBlind = make(map[string]*hsDirEntry)
	}
	s.expireLocked(now)
	if existing, ok := s.byBlind[key]; ok {
		if revision <= existing.revision {
			return false
		}
	} else if len(s.byBlind) >= maxHSDirEntries {
		s.evictOldestLocked()
	}
	s.byBlind[key] = &hsDirEntry{body: canonical, mod: now, revision: revision}
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
	e, ok := s.byBlind[hex.EncodeToString(blinded)]
	if !ok {
		return nil, time.Time{}, false
	}
	return e.body, e.mod, true
}

func (s *hsDirStore) expireLocked(now time.Time) {
	if s.byBlind == nil {
		s.byBlind = make(map[string]*hsDirEntry)
		return
	}
	for k, e := range s.byBlind {
		if now.Sub(e.mod) >= hsDirTTL {
			delete(s.byBlind, k)
		}
	}
}

func (s *hsDirStore) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range s.byBlind {
		if first || e.mod.Before(oldest) {
			oldestKey = k
			oldest = e.mod
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.byBlind, oldestKey)
	}
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
	writeDirBody(w, r, body, mod, false)
}
