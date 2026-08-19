package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/protocol"
)

// VerifyServerDescriptorDocument 按 dir-spec 校验已签名的服务端描述符。
// 供发布前自检、单测以及后续 AI 复用：交叉证书或签名不对就不要上传。
func VerifyServerDescriptorDocument(raw []byte, edID ed25519.PublicKey, rsaID *rsa.PublicKey, ntorPub []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty descriptor")
	}
	idCertDER, err := extractPEMAfterKeyword(raw, "identity-ed25519", "ED25519 CERT")
	if err != nil {
		return fmt.Errorf("identity-ed25519: %w", err)
	}
	idCert, err := protocol.ParseEd25519Certificate(idCertDER)
	if err != nil {
		return fmt.Errorf("parse identity-ed25519: %w", err)
	}
	if idCert.CertType != uint8(protocol.CertTypeEd25519Signing) {
		return fmt.Errorf("identity-ed25519 type %d, want 4", idCert.CertType)
	}
	if err := idCert.VerifySignature(edID); err != nil {
		return fmt.Errorf("identity-ed25519 signature: %w", err)
	}
	if ext := idCert.SignedWithEd25519Key(); ext != nil && !bytes.Equal(ext, edID) {
		return fmt.Errorf("identity-ed25519 signed-with-ed25519-key mismatch")
	}

	tapPub, err := extractRSAPublicAfterKeyword(raw, "onion-key")
	if err != nil {
		return fmt.Errorf("onion-key: %w", err)
	}
	tapCross, err := extractPEMAfterKeyword(raw, "onion-key-crosscert", "CROSSCERT")
	if err != nil {
		return fmt.Errorf("onion-key-crosscert: %w", err)
	}
	payload := onionKeyCrosscertPayload(rsaID, edID)
	if err := rsa.VerifyPKCS1v15(tapPub, 0, payload, tapCross); err != nil {
		return fmt.Errorf("onion-key-crosscert verify: %w", err)
	}

	bit, ntorCertDER, err := extractNtorCrosscert(raw)
	if err != nil {
		return err
	}
	ntorCert, err := protocol.ParseEd25519Certificate(ntorCertDER)
	if err != nil {
		return fmt.Errorf("parse ntor-onion-key-crosscert: %w", err)
	}
	if ntorCert.CertType != uint8(protocol.CertTypeNtorOnionKeyCrossCert) {
		return fmt.Errorf("ntor-onion-key-crosscert type %d, want 10", ntorCert.CertType)
	}
	if !bytes.Equal(ntorCert.CertifiedKey, edID) {
		return fmt.Errorf("ntor-onion-key-crosscert certified key is not Ed25519 identity")
	}
	ntorEdPub, err := crypto.Ed25519PublicFromX25519(ntorPub, bit)
	if err != nil {
		return err
	}
	if err := ntorCert.VerifySignature(ntorEdPub); err != nil {
		return fmt.Errorf("ntor-onion-key-crosscert verify: %w", err)
	}

	if err := verifyRouterEd25519Sig(raw, idCert.CertifiedKey); err != nil {
		return err
	}
	return verifyRouterRSASig(raw, rsaID)
}

func verifyRouterEd25519Sig(raw []byte, signPub ed25519.PublicKey) error {
	const marker = "router-sig-ed25519 "
	idx := bytes.Index(raw, []byte(marker))
	if idx < 0 {
		return fmt.Errorf("missing router-sig-ed25519")
	}
	rest := raw[idx+len(marker):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return fmt.Errorf("truncated router-sig-ed25519")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(rest[:nl])))
	if err != nil {
		return fmt.Errorf("router-sig-ed25519 base64: %w", err)
	}
	signed := make([]byte, 0, len(routerEd25519SigPrefix)+idx+len(marker))
	signed = append(signed, routerEd25519SigPrefix...)
	signed = append(signed, raw[:idx+len(marker)]...)
	sum := sha256.Sum256(signed)
	if !ed25519.Verify(signPub, sum[:], sig) {
		return fmt.Errorf("router-sig-ed25519 verify failed")
	}
	return nil
}

func verifyRouterRSASig(raw []byte, rsaID *rsa.PublicKey) error {
	const marker = "router-signature\n"
	idx := bytes.Index(raw, []byte(marker))
	if idx < 0 {
		return fmt.Errorf("missing router-signature")
	}
	block, _ := pem.Decode(raw[idx+len(marker):])
	if block == nil || block.Type != "SIGNATURE" {
		return fmt.Errorf("missing SIGNATURE PEM")
	}
	h := sha1.Sum(raw[:idx+len(marker)]) // #nosec G401
	if err := rsa.VerifyPKCS1v15(rsaID, 0, h[:], block.Bytes); err != nil {
		return fmt.Errorf("router-signature verify: %w", err)
	}
	return nil
}

func extractNtorCrosscert(raw []byte) (int, []byte, error) {
	const prefix = "ntor-onion-key-crosscert "
	idx := bytes.Index(raw, []byte(prefix))
	if idx < 0 {
		return 0, nil, fmt.Errorf("missing ntor-onion-key-crosscert")
	}
	lineEnd := bytes.IndexByte(raw[idx:], '\n')
	if lineEnd < 0 {
		return 0, nil, fmt.Errorf("truncated ntor-onion-key-crosscert")
	}
	line := strings.TrimSpace(string(raw[idx : idx+lineEnd]))
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return 0, nil, fmt.Errorf("ntor-onion-key-crosscert wants Bit, got %q", line)
	}
	bit, err := strconv.Atoi(fields[1])
	if err != nil || (bit != 0 && bit != 1) {
		return 0, nil, fmt.Errorf("invalid ntor-onion-key-crosscert Bit %q", fields[1])
	}
	der, err := extractPEMAt(raw[idx+lineEnd+1:], "ED25519 CERT")
	if err != nil {
		return 0, nil, fmt.Errorf("ntor-onion-key-crosscert PEM: %w", err)
	}
	return bit, der, nil
}

func extractRSAPublicAfterKeyword(raw []byte, keyword string) (*rsa.PublicKey, error) {
	der, err := extractPEMAfterKeyword(raw, keyword, "RSA PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func extractPEMAfterKeyword(raw []byte, keyword, pemType string) ([]byte, error) {
	marker := []byte(keyword + "\n")
	idx := bytes.Index(raw, marker)
	if idx < 0 {
		return nil, fmt.Errorf("missing %s", keyword)
	}
	return extractPEMAt(raw[idx+len(marker):], pemType)
}

func extractPEMAt(raw []byte, pemType string) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if pemType != "" && block.Type != pemType {
		return nil, fmt.Errorf("PEM type %q, want %q", block.Type, pemType)
	}
	return block.Bytes, nil
}
