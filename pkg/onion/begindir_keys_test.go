package onion

import (
	"context"
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/path"
)

type recordingKeyLoader struct {
	called int
}

func (s *recordingKeyLoader) FetchMicrodescriptorsFor(_ context.Context, relays []*directory.Relay) error {
	s.called++
	for _, r := range relays {
		if r == nil {
			continue
		}
		if len(r.RSAIdentity) != 20 {
			r.RSAIdentity = []byte("01234567890123456789")
		}
		if len(r.NtorOnionKey) != 32 {
			r.NtorOnionKey = []byte("01234567890123456789012345678901")
		}
		if len(r.IdentityKey) != 32 {
			r.IdentityKey = []byte("abcdefghijklmnopqrstuvwxyz012345")
		}
		if r.MicrodescDigest == "" {
			r.MicrodescDigest = "md-" + r.Nickname
		}
	}
	return nil
}

func TestBegindirFetchesKeysBeforeBuild(t *testing.T) {
	pool := []*directory.Relay{
		hsRelay("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Quintex192"),
		hsRelay("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "L2"),
		hsRelay("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "L2b"),
		hsRelay("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "L2c"),
		hsRelay("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", "L2d"),
	}
	target := hsRelay("1111111111111111111111111111111111111111", "hsdir")
	target.RSAIdentity = []byte("01234567890123456789")
	target.NtorOnionKey = []byte("01234567890123456789012345678901")
	target.IdentityKey = []byte("abcdefghijklmnopqrstuvwxyz012345")
	target.MicrodescDigest = "md-hsdir"
	pool = append(pool, target)

	v := path.NewVanguardSet(path.VanguardConfig{L3Count: -1, Count: 2, AvoidDisk: true}, nil)
	loader := &recordingKeyLoader{}
	f := NewBegindirFetcher(circuit.NewBuilder(circuit.NewManager(), nil), nil)
	f.SetRelays(pool)
	f.SetVanguards(v, nil)
	f.SetMicrodescLoader(loader)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.Fetch(ctx, target, "/tor/hs/3/test")
	if err == nil {
		t.Fatal("cancelled context must not complete the fetch")
	}
	if strings.Contains(err.Error(), "missing ntor keys") {
		t.Fatalf("path keys must be fetched before build, got %v", err)
	}
	if loader.called == 0 {
		t.Fatal("BEGIN_DIR must load microdescriptors before CREATE2")
	}
	filled := 0
	for _, r := range pool[:len(pool)-1] {
		if r.HasNtorKeys() {
			filled++
		}
	}
	if filled == 0 {
		t.Fatal("selected hops must receive ntor keys from the loader")
	}
}

func hsRelay(fp, nick string) *directory.Relay {
	return &directory.Relay{
		Nickname:    nick,
		Fingerprint: fp,
		Address:     "192.0.2.1",
		ORPort:      9001,
		Flags:       []string{"Running", "Valid", "Guard", "Fast", "Stable"},
	}
}
