package circuit

import (
	"encoding/binary"
	"testing"
)

func TestCircpadNegotiateRoundTrip(t *testing.T) {
	n := &CircpadNegotiate{
		Version:     0,
		Command:     CircpadCommandStart,
		MachineType: CircpadMachineCircSetup,
		Unused:      0,
		MachineCtr:  0x01020304,
	}
	payload, err := EncodeCircpadNegotiate(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 8 {
		t.Fatalf("len=%d want 8", len(payload))
	}
	if payload[1] != CircpadCommandStart || payload[2] != CircpadMachineCircSetup {
		t.Fatalf("payload=%x", payload)
	}
	if binary.BigEndian.Uint32(payload[4:8]) != 0x01020304 {
		t.Fatalf("machine_ctr=%x", payload[4:8])
	}
	got, err := DecodeCircpadNegotiate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *n {
		t.Fatalf("got %+v want %+v", got, n)
	}
}

func TestCircpadNegotiatedRoundTrip(t *testing.T) {
	n := &CircpadNegotiated{
		Version:     0,
		Command:     CircpadCommandStart,
		Response:    CircpadResponseOK,
		MachineType: CircpadMachineCircSetup,
		MachineCtr:  7,
	}
	payload, err := EncodeCircpadNegotiated(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 8 || payload[2] != CircpadResponseOK {
		t.Fatalf("payload=%x", payload)
	}
	got, err := DecodeCircpadNegotiated(payload)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *n {
		t.Fatalf("got %+v want %+v", got, n)
	}
}

func TestCircpadNegotiateRejectsBadCommand(t *testing.T) {
	if _, err := EncodeCircpadNegotiate(&CircpadNegotiate{Command: 99}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DecodeCircpadNegotiate([]byte{0, 1, 1}); err == nil {
		t.Fatal("short payload must fail")
	}
}

func TestClientHideIntroStateTable(t *testing.T) {
	m := ClientHideIntroCircuits()
	if m.TargetHop != 2 || !m.SendsNegotiate || !m.OriginSide {
		t.Fatalf("%+v", m)
	}
	if m.NextState(CircpadStateStart, CircpadEventNonpaddingSent) != CircpadStateObfuscateCircSetup {
		t.Fatal("START + NONPADDING_SENT → OBFUSCATE")
	}
	if m.NextState(CircpadStateObfuscateCircSetup, CircpadEventPaddingSent) != -1 {
		t.Fatal("client intro 机在 OBFUSCATE 不因 PADDING_SENT 转移")
	}
	if m.AllowedPaddingCount != IntroMachineMaxPadding {
		t.Fatalf("allowed=%d", m.AllowedPaddingCount)
	}
}

func TestRelayHideIntroStateTable(t *testing.T) {
	m := RelayHideIntroCircuits()
	if m.LengthUniformMin != IntroMachineMinPadding || m.LengthUniformMax != IntroMachineMaxPadding {
		t.Fatalf("length %d-%d", m.LengthUniformMin, m.LengthUniformMax)
	}
	if m.NextState(CircpadStateObfuscateCircSetup, CircpadEventLengthCount) != CircpadStateEnd {
		t.Fatal("LENGTH_COUNT → END")
	}
	if m.NextState(CircpadStateObfuscateCircSetup, CircpadEventPaddingSent) != CircpadStateObfuscateCircSetup {
		t.Fatal("PADDING_SENT stays in OBFUSCATE")
	}
}

func TestClientHideRendStateTable(t *testing.T) {
	m := ClientHideRendCircuits()
	if m.NextState(CircpadStateStart, CircpadEventNonpaddingSent) != CircpadStateObfuscateCircSetup {
		t.Fatal("START transition")
	}
	if m.NextState(CircpadStateObfuscateCircSetup, CircpadEventPaddingRecv) != CircpadStateEnd {
		t.Fatal("PADDING_RECV → END")
	}
}

func TestCircpadPaddingDisabled(t *testing.T) {
	if CircpadPaddingDisabled(nil) {
		t.Fatal("default enabled")
	}
	if CircpadPaddingDisabled(map[string]int{"circpad_padding_disabled": 0}) {
		t.Fatal("0 means enabled")
	}
	if !CircpadPaddingDisabled(map[string]int{"circpad_padding_disabled": 1}) {
		t.Fatal("1 means disabled")
	}
}

func TestCircpadMachineTypeWireValue(t *testing.T) {
	if CircpadMachineCircSetup != 1 {
		t.Fatal("CIRCPAD_MACHINE_CIRC_SETUP must be 1")
	}
	if PaddingMachineCircuitSetup != 1 {
		t.Fatal("PaddingMachineCircuitSetup must match wire value 1")
	}
	if CircpadCommandStop != 1 || CircpadCommandStart != 2 {
		t.Fatal("STOP=1 START=2 per padding-spec")
	}
}
