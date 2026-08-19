package circuit

import (
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

func TestCircpadHistogramSampleDelayRend(t *testing.T) {
	h := ClientRendObfuscateHistogram()
	for i := 0; i < 50; i++ {
		d, err := h.SampleDelay()
		if err != nil {
			t.Fatal(err)
		}
		if d < 0 || d >= time.Millisecond {
			t.Fatalf("rend delay out of [0,1ms): %v", d)
		}
	}
}

func TestCircpadHistogramSampleDelayRelayIntro(t *testing.T) {
	h := RelayIntroObfuscateHistogram()
	for i := 0; i < 50; i++ {
		d, err := h.SampleDelay()
		if err != nil {
			t.Fatal(err)
		}
		if d < time.Millisecond || d >= 10*time.Millisecond {
			t.Fatalf("relay intro delay out of [1,10ms): %v", d)
		}
	}
}

func TestCircpadHistogramEmptyTokens(t *testing.T) {
	h := CircpadHistogram{Edges: []uint32{0, 1000}, Bins: []uint32{0}}
	d, err := h.SampleDelay()
	if err != nil {
		t.Fatal(err)
	}
	if d != CircpadDelayInfinite {
		t.Fatalf("want infinite, got %v", d)
	}
}

func TestClientHideRendHasHistogram(t *testing.T) {
	m := ClientHideRendCircuits()
	if !m.SendsPadding || len(m.Histogram.Bins) == 0 {
		t.Fatal("rend client machine must send padding with histogram")
	}
	if m.AllowedPaddingCount != 1 {
		t.Fatalf("allowed padding=%d want 1", m.AllowedPaddingCount)
	}
}

func TestCircpadSchedulePaddingSendsDrop(t *testing.T) {
	ctrl := NewCircpadController(CircpadConfig{})
	if err := ctrl.StartHSSetup(HSSetupRend); err != nil {
		t.Fatal(err)
	}
	sent := make(chan byte, 1)
	ctrl.SetPaddingSender(func(rc *cell.RelayCell) error {
		sent <- rc.Command
		return nil
	})
	ctrl.MarkNegotiateSent()
	ctrl.SchedulePaddingAfterNegotiate()
	select {
	case cmd := <-sent:
		if cmd != cell.RelayDrop {
			t.Fatalf("cmd=%d want DROP", cmd)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("timeout waiting for scheduled DROP")
	}
	if ctrl.State() == CircpadStateStart {
		t.Fatal("should have left START after negotiate")
	}
}
