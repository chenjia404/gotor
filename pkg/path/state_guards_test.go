package path

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestGuardManagerPrefersTorState(t *testing.T) {
	dir := t.TempDir()
	sf := &datadir.StateFile{
		Guards: []datadir.GuardRecord{{
			RSAID:    strings.Repeat("AB", 20),
			Nickname: "StateGuard",
			Fields:   map[string]string{"in": "default"},
		}},
	}
	if err := datadir.SaveState(filepath.Join(dir, datadir.StateFileName), sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}
	// 旧 json 不应覆盖 state
	_ = os.WriteFile(filepath.Join(dir, "guard_state.json"), []byte(`{"guards":[{"fingerprint":"FF","nickname":"JSON"}]}`), 0o600)

	gm, err := NewGuardManager(dir, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	guards := gm.GetGuards()
	if len(guards) != 1 || guards[0].Nickname != "StateGuard" {
		t.Fatalf("expected state guard, got %+v", guards)
	}
}

func TestGuardManagerSkipsMalformedStateRSAID(t *testing.T) {
	dir := t.TempDir()
	sf := &datadir.StateFile{
		Guards: []datadir.GuardRecord{{
			RSAID:    "not-a-real-fingerprint",
			Nickname: "Bad",
			Fields:   map[string]string{"in": "default"},
		}},
	}
	if err := datadir.SaveState(filepath.Join(dir, datadir.StateFileName), sf, "Tor 0.4.9.11 (gotor)"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "guard_state.json"), []byte(`{"guards":[{"fingerprint":"`+strings.Repeat("EF", 20)+`","nickname":"JSON","last_used":"2030-01-01T00:00:00Z"}]}`), 0o600)

	gm, err := NewGuardManager(dir, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	guards := gm.GetGuards()
	if len(guards) != 1 || guards[0].Nickname != "JSON" {
		t.Fatalf("无效 rsa_id 应回退 json，got %+v", guards)
	}
}

func TestGuardManagerWritesTorState(t *testing.T) {
	dir := t.TempDir()
	gm, err := NewGuardManager(dir, logger.NewDefault())
	if err != nil {
		t.Fatal(err)
	}
	if err := gm.AddGuard(&directory.Relay{
		Fingerprint: strings.Repeat("CD", 20),
		Nickname:    "Saved",
		Address:     "127.0.0.1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := gm.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := datadir.LoadState(filepath.Join(dir, datadir.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Guards) != 1 || loaded.Guards[0].Nickname != "Saved" {
		t.Fatalf("state %+v", loaded.Guards)
	}
	if _, err := os.Stat(filepath.Join(dir, "guard_state.json")); err != nil {
		t.Fatalf("json compat file missing: %v", err)
	}
}
