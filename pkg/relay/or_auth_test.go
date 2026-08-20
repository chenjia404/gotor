package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/protocol"
)

func TestVerifyAuthenticateType3ValidAndBadSIG(t *testing.T) {
	responder := generateTestRelayKeys(t)
	initiator := generateTestRelayKeys(t)
	certs, _, authPriv := mustInitiatorCERTS(t, initiator)
	slog := bytesRepeatAuth(0xa1, 32)
	clog := bytesRepeatAuth(0xb2, 32)
	tlsSec := bytesRepeatAuth(0xc3, 32)
	auth := mustBuildAuth0003(t, responder, certs, authPriv, slog, clog, tlsSec)
	if err := verifyAuthenticateType3(auth, certs, responder, slog, clog, tlsSec); err != nil {
		t.Fatalf("valid AUTH0003: %v", err)
	}
	auth[authType3SignedLen] ^= 0x01
	if err := verifyAuthenticateType3(auth, certs, responder, slog, clog, tlsSec); err == nil {
		t.Fatal("tampered SIG must fail")
	}
}

func TestVerifyAuthenticateType3RejectsWrongSID(t *testing.T) {
	responder := generateTestRelayKeys(t)
	other := generateTestRelayKeys(t)
	initiator := generateTestRelayKeys(t)
	certs, _, authPriv := mustInitiatorCERTS(t, initiator)
	slog := bytesRepeatAuth(0x11, 32)
	clog := bytesRepeatAuth(0x22, 32)
	tlsSec := bytesRepeatAuth(0x33, 32)
	auth := mustBuildAuth0003(t, responder, certs, authPriv, slog, clog, tlsSec)
	if err := verifyAuthenticateType3(auth, certs, other, slog, clog, tlsSec); err == nil {
		t.Fatal("wrong responder SID_ED must fail")
	}
}

func TestVerifyAuthenticateCellPayload(t *testing.T) {
	responder := generateTestRelayKeys(t)
	initiator := generateTestRelayKeys(t)
	certs, _, authPriv := mustInitiatorCERTS(t, initiator)
	slog := bytesRepeatAuth(0x44, 32)
	clog := bytesRepeatAuth(0x55, 32)
	tlsSec := bytesRepeatAuth(0x66, 32)
	body := mustBuildAuth0003(t, responder, certs, authPriv, slog, clog, tlsSec)
	payload := make([]byte, 4+len(body))
	payload[1] = 3
	payload[2] = byte(len(body) >> 8)
	payload[3] = byte(len(body))
	copy(payload[4:], body)
	if err := verifyAuthenticateCell(payload, certs, responder, slog, clog, tlsSec); err != nil {
		t.Fatal(err)
	}
	payload[1] = 1
	if err := verifyAuthenticateCell(payload, certs, responder, slog, clog, tlsSec); err == nil {
		t.Fatal("type 1 must fail")
	}
}

func TestReceiveInitiatorFinishAcceptsValidAuthenticate(t *testing.T) {
	responder := generateTestRelayKeys(t)
	handler := NewLinkProtocolHandler(responder, nil)
	handler.setCircIDLen(4)
	initiator := generateTestRelayKeys(t)
	certs, certsPayload, authPriv := mustInitiatorCERTS(t, initiator)

	certsCell := cell.NewCell(0, cell.CmdCerts)
	certsCell.Payload = certsPayload
	clogRaw, err := encodeCellBytes(certsCell, 4)
	if err != nil {
		t.Fatal(err)
	}
	clogSum := sha256.Sum256(clogRaw)
	handler.slog = bytesRepeatAuth(0x77, 32)
	tlsSec := bytesRepeatAuth(0x88, 32)
	authBody := mustBuildAuth0003(t, responder, certs, authPriv, handler.slog, clogSum[:], tlsSec)
	authCell := cell.NewCell(0, cell.CmdAuthenticate)
	authCell.Payload = make([]byte, 4+len(authBody))
	authCell.Payload[1] = 3
	authCell.Payload[2] = byte(len(authBody) >> 8)
	authCell.Payload[3] = byte(len(authBody))
	copy(authCell.Payload[4:], authBody)
	netinfo := cell.NewCell(0, cell.CmdNetinfo)
	netinfo.Payload = []byte{0, 0, 0, 1, 0x04, 4, 127, 0, 0, 1, 0}

	var buf []byte
	for _, c := range []*cell.Cell{certsCell, authCell, netinfo} {
		raw, err := encodeCellBytes(c, 4)
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, raw...)
	}
	conn := newMockConn()
	conn.addReadData(buf)
	orConn := &ServerORConnection{}
	if err := handler.receiveInitiatorFinishWithSecrets(context.Background(), conn, orConn, tlsSec); err != nil {
		t.Fatal(err)
	}
	if !orConn.authenticated {
		t.Fatal("expected authenticated")
	}
}

func mustInitiatorCERTS(t *testing.T, keys *RelayKeys) (*protocol.CERTSCell, []byte, ed25519.PrivateKey) {
	t.Helper()
	expires := time.Now().UTC().Add(24 * time.Hour)
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type4, err := buildIdentitySigningCert(keys.Ed25519Private, signPub, expires)
	if err != nil {
		t.Fatal(err)
	}
	type6, err := buildLinkAuthCert(signPriv, authPub, expires)
	if err != nil {
		t.Fatal(err)
	}
	type7, err := protocol.EncodeRSAEd25519CrossCert(keys.Ed25519Public, keys.RSAPrivate, expires)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeCERTSPayload([]certsEntry{
		{byte(protocol.CertTypeRSAID), keys.TLSCert},
		{byte(protocol.CertTypeEd25519Signing), type4},
		{byte(protocol.CertTypeEd25519Auth), type6},
		{byte(protocol.CertTypeEd25519Identity), type7},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.ParseCERTSCell(&cell.Cell{Command: cell.CmdCerts, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.ValidateSignatures(); err != nil {
		t.Fatal(err)
	}
	return parsed, payload, authPriv
}

func mustBuildAuth0003(t *testing.T, responder *RelayKeys, certs *protocol.CERTSCell, authPriv ed25519.PrivateKey, slog, clog, tlsSec []byte) []byte {
	t.Helper()
	cidED, err := certs.Ed25519IdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	cid, err := initiatorCIDFromCERTS(certs)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, authType3AuthLen)
	copy(auth[0:8], []byte(authType3Tag))
	copy(auth[8:40], cid)
	copy(auth[40:72], rsaIdentitySHA256(&responder.RSAPrivate.PublicKey))
	copy(auth[72:104], cidED)
	copy(auth[104:136], responder.Ed25519Public)
	copy(auth[136:168], slog)
	copy(auth[168:200], clog)
	scert := sha256.Sum256(responder.TLSCert)
	copy(auth[200:232], scert[:])
	copy(auth[232:264], tlsSec)
	if _, err := rand.Read(auth[264:288]); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(authPriv, auth[:authType3SignedLen])
	copy(auth[288:], sig)
	return auth
}

func bytesRepeatAuth(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
