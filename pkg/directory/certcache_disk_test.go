package directory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestValidateAuthorityCertExpired(t *testing.T) {
	a := generateTestAuthorityExpiring(t, "expired", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := validateAuthorityCert(a.cert, a.dir.V3Ident, a.sigFP); err == nil {
		t.Fatal("过期证书必须失败")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want expired", err)
	}
}

func TestCertDiskCacheRoundTrip(t *testing.T) {
	a := generateTestAuthority(t, "diskauth")
	withTestAuthorities(t, []*testAuthority{a})
	dir := t.TempDir()

	src := &AuthorityCertCache{
		certs:  map[string]*AuthorityCert{a.dir.V3Ident: a.cert},
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := src.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	src.persistToDisk()

	path := filepath.Join(dir, cachedCertsFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "dir-key-certificate-version 3") {
		t.Fatal("cached-certs 应为 C Tor 文本格式")
	}

	dst := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := dst.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	got := dst.certs[a.dir.V3Ident]
	if got == nil {
		t.Fatal("应从磁盘加载证书")
	}
	if err := validateAuthorityCert(got, a.dir.V3Ident, a.sigFP); err != nil {
		t.Fatalf("加载后验签失败: %v", err)
	}
	if !cacheFresh(got) {
		t.Fatal("未过期的磁盘证书应可用")
	}
}

func TestCertDiskCacheSkipsExpired(t *testing.T) {
	a := generateTestAuthorityExpiring(t, "expired", time.Now().UTC().Add(-time.Hour))
	withTestAuthorities(t, []*testAuthority{a})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte(a.certPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	if cache.certs[a.dir.V3Ident] != nil {
		t.Fatal("过期证书不得进入内存缓存")
	}
}

func TestCertDiskCacheSkipsUnknownIdentity(t *testing.T) {
	a := generateTestAuthority(t, "stranger")
	// 不调用 withTestAuthorities：identity 不在 KnownAuthorities。
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte(a.certPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	if len(cache.certs) != 0 {
		t.Fatal("未知权威的证书不得加载")
	}
}

func TestCertDiskCacheSkipsTampered(t *testing.T) {
	a := generateTestAuthority(t, "tamper")
	withTestAuthorities(t, []*testAuthority{a})
	tampered := strings.Replace(a.certPEM, a.dir.V3Ident, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 1)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	if len(cache.certs) != 0 {
		t.Fatal("篡改证书不得加载")
	}
}

func TestCertDiskCacheGetUsesDiskWithoutHTTP(t *testing.T) {
	a := generateTestAuthority(t, "offline")
	withTestAuthorities(t, []*testAuthority{a})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte(a.certPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get(context.Background(), a.dir.V3Ident, srv.Client(), []string{srv.URL + "/tor/status-vote/current/consensus-microdesc"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity != a.dir.V3Ident {
		t.Fatalf("identity = %s", got.Identity)
	}
	if hits != 0 {
		t.Fatalf("磁盘命中后不应访问网络, hits=%d", hits)
	}
}

func TestFetchPersistsThenReload(t *testing.T) {
	a := generateTestAuthority(t, "persist")
	withTestAuthorities(t, []*testAuthority{a})
	dir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tor/keys/fp/"+a.dir.V3Ident {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(a.certPEM))
	}))
	defer srv.Close()

	client := NewClient(logger.NewDefault())
	if err := client.EnableCertDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	client.httpClient = srv.Client()
	client.authorities = []string{srv.URL + "/tor/status-vote/current/consensus-microdesc"}

	got, err := client.certCache.Get(context.Background(), a.dir.V3Ident, client.httpClient, client.authorities)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity != a.dir.V3Ident {
		t.Fatal(got.Identity)
	}

	reloaded := NewClient(logger.NewDefault())
	if err := reloaded.EnableCertDiskCache(dir); err != nil {
		t.Fatal(err)
	}
	if reloaded.certCache.certs[a.dir.V3Ident] == nil {
		t.Fatal("第二次启动应从 cached-certs 恢复")
	}
	if err := validateAuthorityCert(reloaded.certCache.certs[a.dir.V3Ident], a.dir.V3Ident, a.sigFP); err != nil {
		t.Fatalf("恢复后验签: %v", err)
	}
}

func TestEnableCertDiskCacheEmptyDir(t *testing.T) {
	client := NewClient(logger.NewDefault())
	if err := client.EnableCertDiskCache(""); err != nil {
		t.Fatal(err)
	}
}

func TestCertDiskCacheKeepsGoodCertWhenNeighborCorrupt(t *testing.T) {
	a := generateTestAuthority(t, "good")
	withTestAuthorities(t, []*testAuthority{a})
	dir := t.TempDir()
	mixed := a.certPEM + "dir-key-certificate-version 3\nnot-a-valid-cert\n"
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte(mixed), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	if cache.certs[a.dir.V3Ident] == nil {
		t.Fatal("相邻损坏条目不得丢掉已通过验签的证书")
	}
}

func TestCertDiskCacheCorruptFileDoesNotFailEnable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatalf("损坏文件不应让 enable 失败: %v", err)
	}
	if len(cache.certs) != 0 {
		t.Fatal("损坏文件应得到空缓存")
	}
}

func TestCertDiskCacheRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	huge := strings.Repeat("x", maxCachedCertsBytes+1)
	if err := os.WriteFile(filepath.Join(dir, cachedCertsFileName), []byte(huge), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	if err := cache.enableDisk(dir); err != nil {
		t.Fatal(err)
	}
	if len(cache.certs) != 0 {
		t.Fatal("超大文件应被拒绝")
	}
}

func TestCacheFreshExpired(t *testing.T) {
	if cacheFresh(&AuthorityCert{ExpiresAt: time.Now().Add(-time.Second)}) {
		t.Fatal("过期不得视为 fresh")
	}
	if !cacheFresh(&AuthorityCert{ExpiresAt: time.Now().Add(time.Hour)}) {
		t.Fatal("未过期应为 fresh")
	}
	if cacheFresh(nil) {
		t.Fatal("nil 不得 fresh")
	}
}
