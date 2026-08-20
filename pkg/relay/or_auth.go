package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/protocol"
)

const (
	authType3Tag         = "AUTH0003"
	authType3AuthLen     = 8 + 32*8 + 24 + 64 // TYPE..SIG
	authType3SignedLen   = authType3AuthLen - 64
	authTLSExporterLabel = "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"
	authType3AuthTypeOff = 0
	authType3AuthLenOff  = 2
	authType3AuthDataOff = 4
)

// verifyAuthenticateCell 校验发起方 AUTHENTICATE（仅 AuthType 3 / LinkAuth=3）。
// slog / clog 必须是握手抄本的 SHA-256（SLOG 含至 AUTH_CHALLENGE，CLOG 不含 AUTHENTICATE）。
func verifyAuthenticateCell(payload []byte, initiator *protocol.CERTSCell, keys *RelayKeys, slog, clog, tlsSecrets []byte) error {
	if len(payload) < authType3AuthDataOff {
		return fmt.Errorf("AUTHENTICATE too short")
	}
	authType := binary.BigEndian.Uint16(payload[authType3AuthTypeOff:])
	authLen := int(binary.BigEndian.Uint16(payload[authType3AuthLenOff:]))
	if authType != authMethodEd25519SHA256RFC5705 {
		return fmt.Errorf("unsupported AUTHENTICATE type %d", authType)
	}
	if authLen < authType3AuthLen {
		return fmt.Errorf("AUTHENTICATE type 3 length %d", authLen)
	}
	if len(payload) < authType3AuthDataOff+authLen {
		return fmt.Errorf("AUTHENTICATE truncated")
	}
	auth := payload[authType3AuthDataOff : authType3AuthDataOff+authLen]
	return verifyAuthenticateType3(auth, initiator, keys, slog, clog, tlsSecrets)
}

func verifyAuthenticateType3(auth []byte, initiator *protocol.CERTSCell, keys *RelayKeys, slog, clog, tlsSecrets []byte) error {
	if len(auth) < authType3AuthLen {
		return fmt.Errorf("AUTH0003 body too short: %d", len(auth))
	}
	if initiator == nil {
		return fmt.Errorf("AUTHENTICATE without initiator CERTS")
	}
	if keys == nil || len(keys.Ed25519Public) != ed25519.PublicKeySize || keys.RSAPrivate == nil || len(keys.TLSCert) == 0 {
		return fmt.Errorf("responder keys incomplete")
	}
	if err := initiator.ValidateSignatures(); err != nil {
		return fmt.Errorf("initiator CERTS: %w", err)
	}
	type6 := initiator.FindCertificate(protocol.CertTypeEd25519Auth)
	if type6 == nil || type6.Ed25519Cert == nil || len(type6.Ed25519Cert.CertifiedKey) != ed25519.PublicKeySize {
		return fmt.Errorf("initiator CERTS missing type 6 link auth key")
	}
	cidED, err := initiator.Ed25519IdentityKey()
	if err != nil || len(cidED) != 32 {
		return fmt.Errorf("initiator Ed25519 identity: %w", err)
	}
	type2 := initiator.FindCertificate(protocol.CertTypeRSAID)
	if type2 == nil || type2.X509Cert == nil {
		return fmt.Errorf("initiator CERTS missing type 2 RSA identity")
	}
	rsaPub, ok := type2.X509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("initiator type 2 is not RSA")
	}
	wantCID := rsaIdentitySHA256(rsaPub)
	wantSID := rsaIdentitySHA256(&keys.RSAPrivate.PublicKey)
	wantSCERT := sha256.Sum256(keys.TLSCert)

	if !bytes.Equal(auth[0:8], []byte(authType3Tag)) {
		return fmt.Errorf("AUTHENTICATE TYPE is not AUTH0003")
	}
	if !bytes.Equal(auth[8:40], wantCID) {
		return fmt.Errorf("AUTHENTICATE CID mismatch")
	}
	if !bytes.Equal(auth[40:72], wantSID) {
		return fmt.Errorf("AUTHENTICATE SID mismatch")
	}
	if !bytes.Equal(auth[72:104], cidED) {
		return fmt.Errorf("AUTHENTICATE CID_ED mismatch")
	}
	if !bytes.Equal(auth[104:136], keys.Ed25519Public) {
		return fmt.Errorf("AUTHENTICATE SID_ED mismatch")
	}
	if !bytes.Equal(auth[136:168], slog) {
		return fmt.Errorf("AUTHENTICATE SLOG mismatch")
	}
	if !bytes.Equal(auth[168:200], clog) {
		return fmt.Errorf("AUTHENTICATE CLOG mismatch")
	}
	if !bytes.Equal(auth[200:232], wantSCERT[:]) {
		return fmt.Errorf("AUTHENTICATE SCERT mismatch")
	}
	if !bytes.Equal(auth[232:264], tlsSecrets) {
		return fmt.Errorf("AUTHENTICATE TLSSECRETS mismatch")
	}
	signed := auth[:authType3SignedLen]
	sig := auth[authType3SignedLen:authType3AuthLen]
	if !ed25519.Verify(type6.Ed25519Cert.CertifiedKey, signed, sig) {
		return fmt.Errorf("AUTHENTICATE SIG invalid")
	}
	return nil
}

func rsaIdentitySHA256(pub *rsa.PublicKey) []byte {
	der := x509.MarshalPKCS1PublicKey(pub)
	sum := sha256.Sum256(der)
	return sum[:]
}

func exportLinkAuthTLSSecrets(conn net.Conn, cid []byte) ([]byte, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("AUTHENTICATE requires TLS exporter")
	}
	st := tlsConn.ConnectionState()
	sec, err := st.ExportKeyingMaterial(authTLSExporterLabel, cid, 32)
	if err != nil {
		return nil, fmt.Errorf("TLS exporter: %w", err)
	}
	if len(sec) != 32 {
		return nil, fmt.Errorf("TLS exporter length %d", len(sec))
	}
	return sec, nil
}

func initiatorCIDFromCERTS(initiator *protocol.CERTSCell) ([]byte, error) {
	if initiator == nil {
		return nil, fmt.Errorf("nil CERTS")
	}
	type2 := initiator.FindCertificate(protocol.CertTypeRSAID)
	if type2 == nil || type2.X509Cert == nil {
		return nil, fmt.Errorf("missing type 2")
	}
	rsaPub, ok := type2.X509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("type 2 not RSA")
	}
	return rsaIdentitySHA256(rsaPub), nil
}

func encodeCellBytes(c *cell.Cell, circIDLen int) ([]byte, error) {
	var buf bytes.Buffer
	if err := c.EncodeLink(&buf, circIDLen); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
