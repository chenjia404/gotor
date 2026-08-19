package directory

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// parseAuthorityCerts 解析 /tor/keys/fp/<id> 或 /tor/keys/all 返回的证书文档。
// 一份响应可能包含同一权威的多张轮换证书。
func parseAuthorityCerts(document string) ([]*AuthorityCert, error) {
	parts := splitDirKeyCertificates(document)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no dir-key-certificate-version in authority cert document")
	}

	certs := make([]*AuthorityCert, 0, len(parts))
	for _, part := range parts {
		cert, err := parseOneAuthorityCert(part)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
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

func parseOneAuthorityCert(document string) (*AuthorityCert, error) {
	if !strings.Contains(document, "dir-key-certificate-version") {
		return nil, fmt.Errorf("missing dir-key-certificate-version")
	}

	identityPEM, err := extractPEMAfter(document, "dir-identity-key")
	if err != nil {
		return nil, fmt.Errorf("dir-identity-key: %w", err)
	}
	signingPEM, err := extractPEMAfter(document, "dir-signing-key")
	if err != nil {
		return nil, fmt.Errorf("dir-signing-key: %w", err)
	}

	identityKey, err := parseRSAPublicKeyPEM(identityPEM)
	if err != nil {
		return nil, fmt.Errorf("parse identity key: %w", err)
	}
	signingKey, err := parseRSAPublicKeyPEM(signingPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}

	computed := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(identityKey)))
	cert := &AuthorityCert{
		Identity:    computed,
		IdentityKey: identityKey,
		SigningKey:  signingKey,
		raw:         document,
	}

	if fp := fieldValue(document, "fingerprint"); fp != "" {
		fp = strings.ToUpper(strings.ReplaceAll(fp, " ", ""))
		if fp != computed {
			return nil, fmt.Errorf("fingerprint field %s does not match identity key digest %s", fp, computed)
		}
	}

	if pub := fieldValue(document, "dir-key-published"); pub != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", pub); err == nil {
			cert.Published = t
		}
	}
	exp := fieldValue(document, "dir-key-expires")
	if exp == "" {
		return nil, fmt.Errorf("missing dir-key-expires")
	}
	t, err := time.Parse("2006-01-02 15:04:05", exp)
	if err != nil {
		return nil, fmt.Errorf("parse dir-key-expires: %w", err)
	}
	cert.ExpiresAt = t

	return cert, nil
}

func parseAndSelectAuthorityCert(data []byte, expectedIdentity, signingDigest string) (*AuthorityCert, error) {
	certs, err := parseAuthorityCerts(string(data))
	if err != nil {
		return nil, err
	}
	return selectAuthorityCert(certs, expectedIdentity, signingDigest)
}

func selectAuthorityCert(certs []*AuthorityCert, expectedIdentity, signingDigest string) (*AuthorityCert, error) {
	expectedIdentity = strings.ToUpper(strings.ReplaceAll(expectedIdentity, " ", ""))
	signingDigest = strings.ToUpper(strings.ReplaceAll(signingDigest, " ", ""))

	var lastErr error
	for _, cert := range certs {
		if err := validateAuthorityCert(cert, expectedIdentity, signingDigest); err != nil {
			lastErr = err
			continue
		}
		return cert, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no matching authority certificate")
}

func validateAuthorityCert(cert *AuthorityCert, expectedIdentity, signingDigest string) error {
	if cert == nil || cert.IdentityKey == nil || cert.SigningKey == nil {
		return fmt.Errorf("incomplete authority cert keys")
	}

	idDigest := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(cert.IdentityKey)))
	if expectedIdentity != "" && idDigest != expectedIdentity {
		return fmt.Errorf("identity key digest mismatch: got %s want %s", idDigest, expectedIdentity)
	}
	if cert.Identity != "" && cert.Identity != idDigest {
		return fmt.Errorf("cached identity %s does not match key digest %s", cert.Identity, idDigest)
	}

	if cert.ExpiresAt.IsZero() {
		return fmt.Errorf("authority certificate missing expiry")
	}
	if time.Now().After(cert.ExpiresAt) {
		return fmt.Errorf("authority certificate expired at %s", cert.ExpiresAt.Format(time.RFC3339))
	}

	if err := verifyDirKeyCertification(cert); err != nil {
		return err
	}
	if err := verifyDirKeyCrosscert(cert); err != nil {
		return err
	}

	if signingDigest != "" {
		got := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(cert.SigningKey)))
		if got != signingDigest {
			return fmt.Errorf("signing key digest mismatch: got %s want %s", got, signingDigest)
		}
	}
	return nil
}

func signingKeyMatches(cert *AuthorityCert, signingDigest string) bool {
	if signingDigest == "" {
		return true
	}
	if cert == nil || cert.SigningKey == nil {
		return false
	}
	got := strings.ToUpper(hex.EncodeToString(rsaSHA1Digest(cert.SigningKey)))
	return got == strings.ToUpper(signingDigest)
}

func fieldValue(document, key string) string {
	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, key+" ") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+" "))
		}
	}
	return ""
}

func extractPEMAfter(document, keyword string) ([]byte, error) {
	idx := strings.Index(document, keyword)
	if idx < 0 {
		return nil, fmt.Errorf("missing %s", keyword)
	}
	rest := document[idx:]
	start := strings.Index(rest, "-----BEGIN ")
	if start < 0 {
		return nil, fmt.Errorf("missing PEM after %s", keyword)
	}
	endRel := strings.Index(rest[start:], "-----END ")
	if endRel < 0 {
		return nil, fmt.Errorf("unterminated PEM after %s", keyword)
	}
	tail := rest[start+endRel:]
	nl := strings.Index(tail, "\n")
	if nl < 0 {
		return []byte(rest[start:]), nil
	}
	return []byte(rest[start : start+endRel+nl+1]), nil
}

func parseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	if block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func rsaSHA1Digest(pub *rsa.PublicKey) []byte {
	der := x509.MarshalPKCS1PublicKey(pub)
	sum := sha1.Sum(der)
	return sum[:]
}

func extractDirKeyCertificationSignedBody(document string) ([]byte, error) {
	start := strings.Index(document, "dir-key-certificate-version")
	if start < 0 {
		return nil, fmt.Errorf("missing dir-key-certificate-version")
	}
	const kw = "dir-key-certification\n"
	end := strings.Index(document[start:], kw)
	if end < 0 {
		return nil, fmt.Errorf("missing dir-key-certification terminator")
	}
	return []byte(document[start : start+end+len(kw)]), nil
}

// verifyDirKeyCertification 用 identity 密钥验证 dir-key-certification。
//
// dir-spec：签名覆盖从 dir-key-certificate-version 到
// "dir-key-certification\n"（含），PKCS#1，不含 algorithmIdentifier。
func verifyDirKeyCertification(cert *AuthorityCert) error {
	if cert == nil || cert.IdentityKey == nil {
		return fmt.Errorf("authority cert missing identity key")
	}
	body, err := extractDirKeyCertificationSignedBody(cert.raw)
	if err != nil {
		return err
	}
	sigPEM, err := extractPEMAfter(cert.raw, "dir-key-certification")
	if err != nil {
		return fmt.Errorf("dir-key-certification signature: %w", err)
	}
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return fmt.Errorf("invalid dir-key-certification signature PEM")
	}
	digest := sha1.Sum(body)
	if err := rsa.VerifyPKCS1v15(cert.IdentityKey, crypto.Hash(0), digest[:], block.Bytes); err != nil {
		return fmt.Errorf("dir-key-certification PKCS#1 verify failed: %w", err)
	}
	return nil
}

// verifyDirKeyCrosscert 验证 signing key 对 identity key 的交叉签名。
//
// 实网权威使用 -----BEGIN ID SIGNATURE-----；payload 为 SHA1(PKCS1(identity))。
func verifyDirKeyCrosscert(cert *AuthorityCert) error {
	if cert == nil || cert.IdentityKey == nil || cert.SigningKey == nil {
		return fmt.Errorf("authority cert missing keys for crosscert")
	}
	sigPEM, err := extractPEMAfter(cert.raw, "dir-key-crosscert")
	if err != nil {
		return fmt.Errorf("dir-key-crosscert: %w", err)
	}
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return fmt.Errorf("invalid dir-key-crosscert PEM")
	}
	idDER := x509.MarshalPKCS1PublicKey(cert.IdentityKey)
	digest := sha1.Sum(idDER)
	if err := rsa.VerifyPKCS1v15(cert.SigningKey, crypto.Hash(0), digest[:], block.Bytes); err != nil {
		return fmt.Errorf("dir-key-crosscert PKCS#1 verify failed: %w", err)
	}
	return nil
}
