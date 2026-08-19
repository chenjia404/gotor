package relay

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestCircuitCryptoRoundTrip(t *testing.T) {
	km := make([]byte, 72)
	for i := range km {
		km[i] = byte(i + 1)
	}
	cc, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cell.NewRelayCell(7, cell.RelayBegin, []byte("example.com:80\x00"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 509 {
		pad := make([]byte, 509)
		copy(pad, plain)
		plain = pad
	}
	// simulate client: encrypt with same Kf as server decrypts
	clientFwd, err := newCircuitCrypto(km)
	if err != nil {
		t.Fatal(err)
	}
	// client outbound uses encryptOutbound which is Kb - wrong for BEGIN from client
	// Client uses ForwardCipher (Kf) to encrypt toward exit.
	enc := append([]byte(nil), plain...)
	enc[1], enc[2] = 0, 0
	enc[5], enc[6], enc[7], enc[8] = 0, 0, 0, 0
	cp := append([]byte(nil), enc...)
	_, _ = clientFwd.fwdDigest.Write(cp)
	sum := clientFwd.fwdDigest.Sum(nil)
	copy(enc[5:9], sum[:4])
	clientFwd.fwdCipher.XORKeyStream(enc, enc)

	dec, err := cc.decryptInbound(enc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cell.DecodeRelayCell(dec)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.RelayBegin || got.StreamID != 7 {
		t.Fatalf("got cmd=%d sid=%d", got.Command, got.StreamID)
	}
}

func TestParseBeginAddr(t *testing.T) {
	h, p, err := parseBeginAddr([]byte("example.com:443\x00"))
	if err != nil || h != "example.com" || p != 443 {
		t.Fatalf("%s %d %v", h, p, err)
	}
}

func TestExitPolicyFromConfigAllowsHTTP(t *testing.T) {
	p := NewExitPolicyFromConfig(true, []string{
		"accept *:80",
		"accept *:443",
		"reject *:*",
	}, false, false, logger.NewDefault())
	ok, _ := p.CheckExitAllowed("93.184.216.34", 80)
	if !ok {
		t.Fatal("80 should allow")
	}
	ok, _ = p.CheckExitAllowed("93.184.216.34", 25)
	if ok {
		t.Fatal("25 should reject")
	}
}
