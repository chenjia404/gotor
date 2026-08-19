package circuit

import "testing"

func TestDefaultCCParamsMatchCTor(t *testing.T) {
	p := DefaultCCParams()
	if p.CwndInit != 124 || p.CwndMin != 124 {
		t.Fatalf("cwnd_init/min = %d/%d, C Tor CIRCWINDOW_INIT=124", p.CwndInit, p.CwndMin)
	}
	if p.CwndInc != 1 || p.CwndIncRate != 31 || p.CwndIncPctSS != 100 {
		t.Fatalf("inc params = %+v", p)
	}
	if p.VegasAlpha != 186 || p.VegasBeta != 248 || p.VegasGamma != 186 || p.VegasDelta != 310 {
		t.Fatalf("vegas exit thresholds = a=%d b=%d g=%d d=%d", p.VegasAlpha, p.VegasBeta, p.VegasGamma, p.VegasDelta)
	}
	if p.SSCap != 600 || p.SSMax != 5000 {
		t.Fatalf("ss cap/max = %d/%d", p.SSCap, p.SSMax)
	}
	if p.CwndFullGap != 4 || p.CwndFullMinPct != 25 || p.CwndFullPerCwnd != 1 {
		t.Fatalf("full heuristics = gap=%d minpct=%d per=%d", p.CwndFullGap, p.CwndFullMinPct, p.CwndFullPerCwnd)
	}
}

func TestCCParamsFromConsensusOverrides(t *testing.T) {
	p := CCParamsFromConsensus(map[string]int{
		"cc_cwnd_inc":         1,
		"cc_cwnd_inc_rate":    31,
		"cc_cwnd_min":         124,
		"cc_vegas_alpha_exit": 186,
		"cc_vegas_delta_exit": 310,
		"cc_sscap_exit":       600,
		"cc_cwnd_full_gap":    4,
		"cc_cwnd_full_minpct": 25,
	})
	if p.VegasAlpha != 186 || p.VegasDelta != 310 || p.SSCap != 600 {
		t.Fatalf("exit overrides not applied: %+v", p)
	}
	if p.VegasBeta != 248 || p.VegasGamma != 186 {
		t.Fatalf("missing consensus keys must keep C Tor defaults, beta=%d gamma=%d", p.VegasBeta, p.VegasGamma)
	}
	if p.CwndInit != 124 {
		t.Fatalf("cc_cwnd_init 未出现时应为 124，got %d", p.CwndInit)
	}
}

func TestCCParamsFromConsensusClamps(t *testing.T) {
	p := CCParamsFromConsensus(map[string]int{
		"cc_cwnd_init":        1,
		"cc_cwnd_inc":         0,
		"cc_vegas_alpha_exit": 99999,
		"cc_ewma_max":         1,
	})
	if p.CwndInit != 31 {
		t.Fatalf("cwnd_init below sendme_inc must clamp to 31, got %d", p.CwndInit)
	}
	if p.CwndInc != 1 {
		t.Fatalf("cwnd_inc=0 must clamp to 1, got %d", p.CwndInc)
	}
	if p.VegasAlpha != 1000 {
		t.Fatalf("alpha above 1000 must clamp, got %d", p.VegasAlpha)
	}
	if p.EwmaMax != 2 {
		t.Fatalf("ewma_max below 2 must clamp, got %d", p.EwmaMax)
	}
}

func TestCCParamsFromNilConsensus(t *testing.T) {
	if CCParamsFromConsensus(nil) != DefaultCCParams() {
		t.Fatal("nil params must equal defaults")
	}
}
