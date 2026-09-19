package onion

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/opd-ai/go-tor/pkg/directory"
)

func TestBuildHSIndexReplicaStartsAtOne(t *testing.T) {
	blinded := bytes.Repeat([]byte{0x11}, 32)
	_, err := BuildHSIndex(blinded, 0, 1, 1440)
	if err == nil {
		t.Fatal("replica 0 must fail")
	}
	a, err := BuildHSIndex(blinded, 1, 100, 1440)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildHSIndex(blinded, 2, 100, 1440)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("replicas must differ")
	}
}

func TestBuildHSDirIndexOrder(t *testing.T) {
	id := bytes.Repeat([]byte{0x22}, 32)
	srv := bytes.Repeat([]byte{0x33}, 32)
	a, err := BuildHSDirIndex(id, srv, 5, 1440)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildHSDirIndex(id, srv, 6, 1440)
	if bytes.Equal(a, b) {
		t.Fatal("period must affect index")
	}
}

func TestDisasterSRV(t *testing.T) {
	a := DisasterSRV(10, 1440)
	b := DisasterSRV(11, 1440)
	if len(a) != 32 || bytes.Equal(a, b) {
		t.Fatal(a, b)
	}
}

func TestSelectResponsibleHSDirs(t *testing.T) {
	blinded := bytes.Repeat([]byte{0xaa}, 32)
	srv := DisasterSRV(42, 1440)
	dirs := make([]*HSDirectory, 0, 20)
	for i := 0; i < 20; i++ {
		id := make([]byte, 32)
		id[0] = byte(i + 1)
		id[1] = byte(i * 3)
		r := &directory.Relay{
			IdentityKey: append([]byte(nil), id...),
			Nickname:    fmt.Sprintf("n%d", i),
			Fingerprint: fmt.Sprintf("%040d", i),
		}
		dirs = append(dirs, &HSDirectory{
			Fingerprint: r.Fingerprint,
			Address:     "127.0.0.1",
			ORPort:      9000 + i,
			HSDir:       true,
			Relay:       r,
		})
	}
	got := SelectResponsibleHSDirs(blinded, dirs, srv, 42, 2, 3)
	if len(got) == 0 || len(got) > 6 {
		t.Fatalf("expected 1..6 responsible, got %d", len(got))
	}
	store := SelectResponsibleHSDirsStore(blinded, dirs, srv, 42, 2, 4)
	if len(store) < len(got) || len(store) > 8 {
		t.Fatalf("spread_store should cover fetch set, fetch=%d store=%d", len(got), len(store))
	}
	self := store[0].ed25519Identity()
	if !IsResponsibleHSDir(self, blinded, dirs, srv, 42, 2, 4) {
		t.Fatal("store member must be responsible")
	}
	outsider := bytes.Repeat([]byte{0xff}, 32)
	if IsResponsibleHSDir(outsider, blinded, dirs, srv, 42, 2, 4) {
		t.Fatal("unknown identity must not be responsible")
	}
}

func TestHSDirRingParamsFromConsensus(t *testing.T) {
	def := HSDirRingParamsFromConsensus(nil)
	if def.NReplicas != 2 || def.SpreadFetch != 3 || def.SpreadStore != 4 {
		t.Fatalf("defaults %+v", def)
	}
	got := HSDirRingParamsFromConsensus(map[string]int{
		"hsdir_n_replicas":   0,
		"hsdir_spread_fetch": 999,
		"hsdir_spread_store": 8,
	})
	if got.NReplicas != 1 || got.SpreadFetch != 128 || got.SpreadStore != 8 {
		t.Fatalf("clamp %+v", got)
	}
}
