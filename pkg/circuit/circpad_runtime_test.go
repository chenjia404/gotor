package circuit

import (
	"testing"

	"github.com/opd-ai/go-tor/pkg/cell"
)

func TestCircpadControllerIntroFlow(t *testing.T) {
	ctrl := NewCircpadController(CircpadConfig{})
	if err := ctrl.StartHSSetup(HSSetupIntro); err != nil {
		t.Fatal(err)
	}
	if ctrl.State() != CircpadStateStart {
		t.Fatalf("state=%d", ctrl.State())
	}
	rc, err := ctrl.BuildNegotiateStart()
	if err != nil {
		t.Fatal(err)
	}
	if rc.Command != cell.RelayPaddingNegotiate {
		t.Fatalf("cmd=%d", rc.Command)
	}
	n, err := DecodeCircpadNegotiate(rc.Data)
	if err != nil {
		t.Fatal(err)
	}
	if n.Command != CircpadCommandStart || n.MachineType != CircpadMachineCircSetup || n.MachineCtr != 1 {
		t.Fatalf("%+v", n)
	}
	ctrl.MarkNegotiateSent()
	if ctrl.State() != CircpadStateObfuscateCircSetup {
		t.Fatalf("after negotiate state=%d want OBFUSCATE", ctrl.State())
	}
	if !ctrl.NegotiateSent() || !ctrl.Active() {
		t.Fatal("expected active after negotiate")
	}
	if err := ctrl.OnNegotiated(&CircpadNegotiated{
		Command: CircpadCommandStart, Response: CircpadResponseOK,
		MachineType: CircpadMachineCircSetup, MachineCtr: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if ctrl.State() != CircpadStateObfuscateCircSetup {
		t.Fatal("intro client stays in OBFUSCATE after OK")
	}
}

func TestCircpadControllerRendEndsOnPaddingRecv(t *testing.T) {
	ctrl := NewCircpadController(CircpadConfig{})
	if err := ctrl.StartHSSetup(HSSetupRend); err != nil {
		t.Fatal(err)
	}
	ctrl.MarkNegotiateSent()
	if ctrl.State() != CircpadStateObfuscateCircSetup {
		t.Fatalf("state=%d", ctrl.State())
	}
	ctrl.OnPaddingRecv()
	if ctrl.Active() || ctrl.State() != CircpadStateEnd {
		t.Fatalf("rend should end after padding recv; active=%v state=%d", ctrl.Active(), ctrl.State())
	}
}

func TestCircpadControllerDisabled(t *testing.T) {
	ctrl := NewCircpadController(CircpadConfig{Disabled: true})
	if err := ctrl.StartHSSetup(HSSetupIntro); err == nil {
		t.Fatal("expected error when disabled")
	}
}

func TestCircpadControllerIgnoresWrongCtr(t *testing.T) {
	ctrl := NewCircpadController(CircpadConfig{})
	_ = ctrl.StartHSSetup(HSSetupIntro)
	ctrl.MarkNegotiateSent()
	if err := ctrl.OnNegotiated(&CircpadNegotiated{
		Response: CircpadResponseOK, MachineCtr: 99,
	}); err != nil {
		t.Fatal(err)
	}
	if !ctrl.Active() {
		t.Fatal("wrong ctr must be ignored, stay active")
	}
}

func TestCircpadControllerStop(t *testing.T) {
	ctrl := NewCircpadController(CircpadConfig{})
	_ = ctrl.StartHSSetup(HSSetupIntro)
	rc, err := ctrl.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if rc == nil {
		t.Fatal("expected STOP cell")
	}
	n, err := DecodeCircpadNegotiate(rc.Data)
	if err != nil {
		t.Fatal(err)
	}
	if n.Command != CircpadCommandStop {
		t.Fatalf("cmd=%d", n.Command)
	}
	if ctrl.Active() {
		t.Fatal("should be inactive after stop")
	}
}

func TestSendRelayCellToHopIndexCheck(t *testing.T) {
	c := NewCircuit(1)
	c.State = StateOpen
	c.Hops = []*Hop{{}, {}}
	rc, _ := cell.NewRelayCell(0, cell.RelayPaddingNegotiate, make([]byte, 8))
	if err := c.SendRelayCellToHop(rc, 5); err == nil {
		t.Fatal("out of range hop must fail")
	}
	if err := c.SendRelayCellToHop(rc, -1); err == nil {
		t.Fatal("negative hop must fail")
	}
}

func TestStartHSSetupPaddingRequiresPadding2(t *testing.T) {
	c := NewCircuit(1)
	c.State = StateOpen
	c.Hops = []*Hop{{}, {}, {}}
	err := c.StartHSSetupPadding(HSSetupIntro, false, CircpadConfig{})
	if err == nil {
		t.Fatal("expected error without Padding=2")
	}
	err = c.StartHSSetupPadding(HSSetupIntro, true, CircpadConfig{Disabled: true})
	if err == nil {
		t.Fatal("expected error when disabled")
	}
}
