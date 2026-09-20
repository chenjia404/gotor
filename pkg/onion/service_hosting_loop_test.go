package onion

import (
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestHandleIntroCircuitCellsRejectsWrongAck(t *testing.T) {
	svc, err := NewService(&ServiceConfig{
		NumIntroPoints:         1,
		AllowPlaceholderIntros: true,
		Ports:                  map[int]string{80: "127.0.0.1:8080"},
	}, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	mock := newMockCircuit(42)
	est := make(chan error, 1)
	go svc.handleIntroCircuitCells(mock, est)
	mock.receiveCellsChan <- &cell.RelayCell{Command: cell.RelayIntroduce2, Data: []byte{1}}
	select {
	case err := <-est:
		if err == nil {
			t.Fatal("wrong first cell should fail")
		}
		if !strings.Contains(err.Error(), "38") {
			t.Fatalf("INTRO_ESTABLISHED 是 cmd 38，错误应写出 38，got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ESTABLISH ack error")
	}
}

func TestHandleIntroCircuitCellsThenIntroduce2(t *testing.T) {
	svc, err := NewService(&ServiceConfig{
		NumIntroPoints:         1,
		AllowPlaceholderIntros: true,
		Ports:                  map[int]string{80: "127.0.0.1:8080"},
	}, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}

	mock := newMockCircuit(7)
	svc.introPoints = []*ServiceIntroPoint{{
		CircuitID:   7,
		EncKey:      make([]byte, 32),
		Established: true,
		Relay:       &HSDirectory{Fingerprint: "intro"},
	}}
	est := make(chan error, 1)
	go svc.handleIntroCircuitCells(mock, est)
	mock.receiveCellsChan <- &cell.RelayCell{Command: cell.RelayIntroEstablished}
	select {
	case err := <-est:
		if err != nil {
			t.Fatalf("INTRO_ESTABLISHED: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for INTRO_ESTABLISHED")
	}

	// 非法 INTRODUCE2 应被 Warn 而不是把收包循环打死。
	mock.receiveCellsChan <- &cell.RelayCell{Command: cell.RelayIntroduce2, Data: []byte{0, 1, 2}}
	time.Sleep(50 * time.Millisecond)
	svc.cancel()
}

func TestResponsibleHSDirPoolSeparatesIntros(t *testing.T) {
	keys := func() ([]byte, []byte, []byte) {
		ntor := make([]byte, 32)
		id := make([]byte, 32)
		rsa := make([]byte, 20)
		ntor[0], id[0], rsa[0] = 1, 2, 3
		return ntor, id, rsa
	}
	ntor, id, rsa := keys()
	fastOnly := &directory.Relay{
		Fingerprint:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Address:      "1.1.1.1",
		ORPort:       9001,
		Flags:        []string{"Running", "Valid", "Fast", "Stable"},
		NtorOnionKey: ntor,
		IdentityKey:  id,
		RSAIdentity:  rsa,
	}
	hsdir := &directory.Relay{
		Fingerprint:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		Address:      "2.2.2.2",
		ORPort:       9001,
		DirPort:      9030,
		Flags:        []string{"Running", "Valid", "HSDir", "Fast", "Stable"},
		NtorOnionKey: append([]byte(nil), ntor...),
		IdentityKey:  append([]byte(nil), id...),
		RSAIdentity:  append([]byte(nil), rsa...),
	}
	hsdir.RSAIdentity[0] = 9
	svc, err := NewService(&ServiceConfig{
		AllowPlaceholderIntros: true,
		NetworkRelays:          []*directory.Relay{fastOnly, hsdir},
		Ports:                  map[int]string{80: "127.0.0.1:8080"},
	}, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	introPool := []*HSDirectory{{Fingerprint: fastOnly.Fingerprint, Relay: fastOnly}}
	got := svc.responsibleHSDirPool(introPool)
	if len(got) != 1 || !got[0].HSDir {
		t.Fatalf("上传应走 HSDir，got %+v", got)
	}
}
