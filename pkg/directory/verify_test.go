package directory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

type testAuthority struct {
	dir     DirectoryAuthority
	idPriv  *rsa.PrivateKey
	sigPriv *rsa.PrivateKey
	cert    *AuthorityCert
	certPEM string
	sigFP   string
}

func pemPKCS1Public(pub *rsa.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	}))
}

func generateTestAuthority(t *testing.T, nickname string) *testAuthority {
	t.Helper()
	idPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sigPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	idFP := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(&idPriv.PublicKey)))
	sigFP := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(&sigPriv.PublicKey)))

	var b strings.Builder
	b.WriteString("dir-key-certificate-version 3\n")
	b.WriteString("fingerprint " + idFP + "\n")
	b.WriteString("dir-key-published 2026-01-01 00:00:00\n")
	b.WriteString("dir-key-expires 2028-01-01 00:00:00\n")
	b.WriteString("dir-identity-key\n")
	b.WriteString(pemPKCS1Public(&idPriv.PublicKey))
	b.WriteString("dir-signing-key\n")
	b.WriteString(pemPKCS1Public(&sigPriv.PublicKey))

	idDER := x509.MarshalPKCS1PublicKey(&idPriv.PublicKey)
	ch := sha1.Sum(idDER)
	csig, err := rsa.SignPKCS1v15(rand.Reader, sigPriv, 0, ch[:])
	if err != nil {
		t.Fatal(err)
	}
	b.WriteString("dir-key-crosscert\n")
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "ID SIGNATURE", Bytes: csig}))
	b.WriteString("dir-key-certification\n")

	body := []byte(b.String())
	dh := sha1.Sum(body)
	dsig, err := rsa.SignPKCS1v15(rand.Reader, idPriv, 0, dh[:])
	if err != nil {
		t.Fatal(err)
	}
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE", Bytes: dsig}))

	certPEM := b.String()
	certs, err := parseAuthorityCerts(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuthorityCert(certs[0], idFP, sigFP); err != nil {
		t.Fatal(err)
	}
	certs[0].FetchedAt = time.Now()

	return &testAuthority{
		dir: DirectoryAuthority{
			Nickname: nickname,
			V3Ident:  idFP,
			Address:  "127.0.0.1:80",
		},
		idPriv:  idPriv,
		sigPriv: sigPriv,
		cert:    certs[0],
		certPEM: certPEM,
		sigFP:   sigFP,
	}
}

func withTestAuthorities(t *testing.T, auths []*testAuthority) {
	t.Helper()
	old := KnownAuthorities
	repl := make([]DirectoryAuthority, 0, len(auths))
	for _, a := range auths {
		repl = append(repl, a.dir)
	}
	KnownAuthorities = repl
	t.Cleanup(func() { KnownAuthorities = old })
}

func buildSignedConsensus(t *testing.T, auths []*testAuthority) string {
	t.Helper()
	now := time.Now().UTC()
	core := fmt.Sprintf(`network-status-version 3 microdesc
vote-status consensus
consensus-method 33
valid-after %s
fresh-until %s
valid-until %s
r TestRelay AAAAAAAAAAAAAAAAAAAAAA %s 192.0.2.1 9001 0
m AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
s Fast Guard Running Stable Valid
w Bandwidth=1000
`,
		now.Add(-1*time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(1*time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(3*time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(-2*time.Hour).Format("2006-01-02 15:04:05"),
	)
	signedBody := core + "directory-signature "
	var out strings.Builder
	out.WriteString(core)
	h := sha256.Sum256([]byte(signedBody))
	for _, a := range auths {
		fmt.Fprintf(&out, "directory-signature sha256 %s %s\n", a.dir.V3Ident, a.sigFP)
		sig, err := rsa.SignPKCS1v15(rand.Reader, a.sigPriv, 0, h[:])
		if err != nil {
			t.Fatal(err)
		}
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE", Bytes: sig}))
	}
	return out.String()
}

func TestExtractConsensusSignedBody(t *testing.T) {
	doc := "network-status-version 3 microdesc\nparams foo=1\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nxx\n-----END SIGNATURE-----\n"
	body, err := extractConsensusSignedBody(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := "network-status-version 3 microdesc\nparams foo=1\ndirectory-signature "
	if string(body) != want {
		t.Fatalf("signed body = %q, want %q", body, want)
	}

	if _, err := extractConsensusSignedBody("not a consensus"); err == nil {
		t.Fatal("expected error for missing header")
	}
	if _, err := extractConsensusSignedBody("network-status-version 3\nno signatures"); err == nil {
		t.Fatal("expected error for missing directory-signature")
	}

	// 签名行出现在 version 之前不得 panic，应报错（或只认 version 之后的边界）。
	early := "directory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nxx\n-----END SIGNATURE-----\nnetwork-status-version 3\n"
	if _, err := extractConsensusSignedBody(early); err == nil {
		t.Fatal("directory-signature before version must not yield a signed body")
	}
}

func TestParseAndVerifyGeneratedAuthorityCert(t *testing.T) {
	a := generateTestAuthority(t, "testauth")
	if a.cert.Identity != a.dir.V3Ident {
		t.Fatalf("identity = %s, want %s", a.cert.Identity, a.dir.V3Ident)
	}
	if a.cert.IdentityKey == nil || a.cert.SigningKey == nil {
		t.Fatal("keys missing")
	}
	if !signingKeyMatches(a.cert, a.sigFP) {
		t.Fatal("signing key digest mismatch")
	}

	// 篡改 fingerprint 必须失败
	tampered := strings.Replace(a.certPEM, a.dir.V3Ident, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 1)
	if _, err := parseAuthorityCerts(tampered); err == nil {
		t.Fatal("expected fingerprint/key mismatch")
	}
}

func TestVerifyConsensusSignatures_ValidGenerated(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)

	raw := buildSignedConsensus(t, auths)
	signedBody, err := extractConsensusSignedBody(raw)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(logger.NewDefault())
	client.authorities = nil
	for _, a := range auths {
		client.certCache.certs[a.dir.V3Ident] = a.cert
	}

	relays, meta, err := client.parseConsensusWithMetadata(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 {
		t.Fatalf("relays = %d, want 1", len(relays))
	}
	if err := client.VerifyConsensusSignatures(context.Background(), signedBody, meta); err != nil {
		t.Fatalf("valid signatures rejected: %v", err)
	}
}

func TestVerifyConsensusSignatures_TamperedBody(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)

	raw := buildSignedConsensus(t, auths)
	raw = strings.Replace(raw, "Bandwidth=1000", "Bandwidth=9999", 1)
	signedBody, err := extractConsensusSignedBody(raw)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(logger.NewDefault())
	client.authorities = nil
	for _, a := range auths {
		client.certCache.certs[a.dir.V3Ident] = a.cert
	}
	_, meta, err := client.parseConsensusWithMetadata(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyConsensusSignatures(context.Background(), signedBody, meta); err == nil {
		t.Fatal("tampered consensus must fail signature verification")
	}
}

func TestVerifyConsensusSignatures_Quorum(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)

	raw := buildSignedConsensus(t, auths[:4])
	signedBody, err := extractConsensusSignedBody(raw)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(logger.NewDefault())
	client.authorities = nil
	for _, a := range auths {
		client.certCache.certs[a.dir.V3Ident] = a.cert
	}
	_, meta, err := client.parseConsensusWithMetadata(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	err = client.VerifyConsensusSignatures(context.Background(), signedBody, meta)
	if err == nil {
		t.Fatal("4 of 5 signatures must fail quorum")
	}
	if !strings.Contains(err.Error(), "insufficient") {
		t.Fatalf("error = %v, want insufficient", err)
	}
}

func TestFetchFromAuthority_RequiresValidSignatures(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)
	raw := buildSignedConsensus(t, auths)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tor/keys/fp/") {
			id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
			for _, a := range auths {
				if a.dir.V3Ident == id {
					w.Write([]byte(a.certPEM))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "consensus") {
			w.Write([]byte(raw))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(logger.NewDefault())
	client.httpClient = server.Client()
	client.authorities = []string{server.URL + "/tor/status-vote/current/consensus-microdesc"}

	relays, err := client.FetchConsensus(context.Background())
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("relays = %d, want 1", len(relays))
	}

	// 篡改后的共识即使 metadata 个数够也必须拒绝
	tampered := strings.Replace(raw, "Bandwidth=1000", "Bandwidth=1", 1)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tor/keys/fp/") {
			id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
			for _, a := range auths {
				if a.dir.V3Ident == id {
					w.Write([]byte(a.certPEM))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(tampered))
	}))
	defer bad.Close()

	client.httpClient = bad.Client()
	client.authorities = []string{bad.URL + "/tor/status-vote/current/consensus-microdesc"}
	if _, err := client.FetchConsensus(context.Background()); err == nil {
		t.Fatal("tampered consensus must be rejected by FetchConsensus")
	}
}

func TestFetchFromAuthority_IgnoresUnsignedRelayInjection(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)
	core := buildSignedConsensus(t, auths)
	injected := "r EvilPrefix BBBBBBBBBBBBBBBBBBBBBB 2026-01-01 00:00:00 198.51.100.1 9001 0\ns Exit Fast Guard Running Stable Valid\n" +
		core +
		"r EvilSuffix CCCCCCCCCCCCCCCCCCCCCC 2026-01-01 00:00:00 203.0.113.1 9001 0\ns Exit Fast Guard Running Stable Valid\n" +
		"valid-until 2099-01-01 00:00:00\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tor/keys/fp/") {
			id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
			for _, a := range auths {
				if a.dir.V3Ident == id {
					w.Write([]byte(a.certPEM))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(injected))
	}))
	defer server.Close()

	client := NewClient(logger.NewDefault())
	client.httpClient = server.Client()
	client.authorities = []string{server.URL + "/tor/status-vote/current/consensus-microdesc"}

	relays, err := client.FetchConsensus(context.Background())
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	if len(relays) != 1 || relays[0].Nickname != "TestRelay" {
		t.Fatalf("unsigned injected relays leaked into result: %+v", relays)
	}

	signed, err := extractConsensusSignedBody(injected)
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err := client.parseConsensusWithMetadata(strings.NewReader(string(signed)))
	if err != nil {
		t.Fatal(err)
	}
	if meta.ValidUntil.Year() == 2099 {
		t.Fatal("unsigned valid-until must not overwrite signed metadata")
	}
}

func TestAuthorityCertCacheGet_FPEndpoint(t *testing.T) {
	a := generateTestAuthority(t, "cacheauth")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tor/keys/fp/"+a.dir.V3Ident {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(a.certPEM))
	}))
	defer server.Close()

	cache := &AuthorityCertCache{
		certs:  make(map[string]*AuthorityCert),
		logger: logger.NewDefault().Component("certcache"),
	}
	cert, err := cache.Get(context.Background(), a.dir.V3Ident, server.Client(), []string{server.URL + "/tor/status-vote/current/consensus"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cert.Identity != a.dir.V3Ident {
		t.Fatalf("identity = %s", cert.Identity)
	}
	cert2, err := cache.Get(context.Background(), a.dir.V3Ident, server.Client(), []string{server.URL + "/tor/status-vote/current/consensus"})
	if err != nil {
		t.Fatal(err)
	}
	if cert2 != cert {
		t.Fatal("expected cached certificate pointer")
	}
}
