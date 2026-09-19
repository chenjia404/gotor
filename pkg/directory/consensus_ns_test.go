package directory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistNSDoesNotOverwriteMicrodesc(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(nil)
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableNSConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	md := "network-status-version 3 microdesc\nmd-body\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nM\n-----END SIGNATURE-----\n"
	ns := "network-status-version 3\nns-body\ndirectory-signature sha256 CC DD\n-----BEGIN SIGNATURE-----\nN\n-----END SIGNATURE-----\n"
	c.persistConsensusDisk(md)
	c.persistNSConsensusDisk(ns)

	gotMD, err := os.ReadFile(filepath.Join(dir, cachedMicrodescConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotMD) != md {
		t.Fatalf("microdesc 文件被覆盖: %q", gotMD)
	}
	gotNS, err := os.ReadFile(filepath.Join(dir, cachedNSConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotNS) != ns {
		t.Fatalf("ns 文件内容不对: %q", gotNS)
	}

	c.persistConsensusDisk(ns)
	gotMD, err = os.ReadFile(filepath.Join(dir, cachedMicrodescConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotMD) != md {
		t.Fatal("ns 文档不得写入 cached-microdesc-consensus")
	}
	c.persistNSConsensusDisk(md)
	gotNS, err = os.ReadFile(filepath.Join(dir, cachedNSConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotNS) != ns {
		t.Fatal("microdesc 文档不得写入 cached-consensus")
	}
}

func TestFetchNSConsensusDocumentStoresSeparately(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, "nsauth"+string(rune('0'+i)))
	}
	withTestAuthorities(t, auths)
	nsDoc := buildSignedNSConsensus(t, auths)
	mdDoc := buildSignedConsensus(t, auths)

	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nsDoc))
	})
	mux.HandleFunc("/tor/status-vote/current/consensus-microdesc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(mdDoc))
	})
	mux.HandleFunc("/tor/keys/fp/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
		for _, a := range auths {
			if a.dir.V3Ident == id {
				_, _ = w.Write([]byte(a.certPEM))
				return
			}
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	c := NewClient(nil)
	c.httpClient = srv.Client()
	c.authorities = []string{srv.URL + "/tor/status-vote/current/consensus-microdesc"}
	if err := c.EnableConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableNSConsensusDiskCache(dir); err != nil {
		t.Fatal(err)
	}

	relays, err := c.FetchConsensus(context.Background())
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	if len(relays) == 0 {
		t.Fatal("microdesc 共识应解析出 relay")
	}
	if err := c.FetchNSConsensusDocument(context.Background()); err != nil {
		t.Fatalf("FetchNSConsensusDocument: %v", err)
	}

	gotNS, err := os.ReadFile(filepath.Join(dir, cachedNSConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(gotNS), "network-status-version 3\n") {
		t.Fatalf("ns 文件应是 ns flavor")
	}
	if strings.Contains(string(gotNS), "network-status-version 3 microdesc") {
		t.Fatal("ns 文件不得含 microdesc flavor 标记")
	}
	gotMD, err := os.ReadFile(filepath.Join(dir, cachedMicrodescConsensusName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotMD), "network-status-version 3 microdesc") {
		t.Fatal("microdesc 文件应保持 microdesc flavor")
	}
	if c.copyLastConsensusRaw() == c.copyNSConsensusRaw() {
		t.Fatal("选路缓存与 ns 缓存不得是同一份文档")
	}
}

func TestFetchNSConsensusDocumentDisabled(t *testing.T) {
	c := NewClient(nil)
	if err := c.FetchNSConsensusDocument(context.Background()); err == nil {
		t.Fatal("未 EnableNSConsensusDiskCache 必须失败")
	}
}

func TestAcceptNSConsensusRejectsMicrodesc(t *testing.T) {
	a := generateTestAuthority(t, "nsauth")
	withTestAuthorities(t, []*testAuthority{a})
	c := NewClient(nil)
	if err := c.EnableNSConsensusDiskCache(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := c.acceptNSConsensus(context.Background(), buildSignedConsensus(t, []*testAuthority{a})); err == nil {
		t.Fatal("microdesc 文档不得被当成 ns 收下")
	}
}
