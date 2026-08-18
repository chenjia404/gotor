package circuit

import "crypto/rand"

type stubRelay struct {
	rsa  []byte
	ntor []byte
	ed   []byte
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

func (s *stubRelay) HasNtorKeys() bool      { return len(s.rsa) == 20 && len(s.ntor) == 32 }
func (s *stubRelay) GetNtorOnionKey() []byte { return s.ntor }
func (s *stubRelay) RSAIdentityBytes() []byte { return s.rsa }
func (s *stubRelay) GetIdentityKey() []byte { return s.ed }
func (s *stubRelay) String() string         { return "127.0.0.1:9001" }
func (s *stubRelay) GetFingerprintHex() string {
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
