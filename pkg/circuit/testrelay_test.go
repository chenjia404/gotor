package circuit

import (
	"crypto/rand"
	"net"
)

type stubRelay struct {
	rsa        []byte
	ntor       []byte
	ed         []byte
	ipv6       net.IP
	ipv6Port   uint16
	noIPv6Spec bool // 有 IPv6 地址但不宣告 Relay=3 时为 true
}

func newStubRelay() *stubRelay {
	s := &stubRelay{
		rsa:  make([]byte, 20),
		ntor: make([]byte, 32),
		ed:   make([]byte, 32),
	}
	_, _ = rand.Read(s.rsa)
	_, _ = rand.Read(s.ntor)
	_, _ = rand.Read(s.ed)
	return s
}

func (s *stubRelay) HasNtorKeys() bool        { return len(s.rsa) == 20 && len(s.ntor) == 32 }
func (s *stubRelay) GetNtorOnionKey() []byte  { return s.ntor }
func (s *stubRelay) RSAIdentityBytes() []byte { return s.rsa }
func (s *stubRelay) GetIdentityKey() []byte   { return s.ed }
func (s *stubRelay) String() string           { return "127.0.0.1:9001" }
func (s *stubRelay) GetFingerprintHex() string {
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

func (s *stubRelay) IPv6ORAddress() (net.IP, uint16, bool) {
	if s.ipv6 == nil || s.ipv6Port == 0 {
		return nil, 0, false
	}
	return s.ipv6, s.ipv6Port, true
}

func (s *stubRelay) ShouldIncludeExtendIPv6() bool {
	if s.noIPv6Spec {
		return false
	}
	_, _, ok := s.IPv6ORAddress()
	return ok
}
