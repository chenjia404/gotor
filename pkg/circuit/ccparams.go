package circuit

// CCParams 是 FlowCtrl=2 / proposal 324 的共识参数。
// 缺省值对照 C Tor congestion_control_common.c / congestion_control_vegas.c
// 与 2026-08 共识（未列出的项用 C Tor 默认）。
//
// Exit 电路用 *_exit / cc_sscap_exit；洋葱会合电路用
// CCParamsOnionFromConsensus 读 *_onion / cc_sscap_onion。
type CCParams struct {
	CwndInit        int // cc_cwnd_init
	CwndMin         int // cc_cwnd_min
	CwndMax         int // cc_cwnd_max
	CwndInc         int // cc_cwnd_inc
	CwndIncRate     int // cc_cwnd_inc_rate
	CwndIncPctSS    int // cc_cwnd_inc_pct_ss
	VegasAlpha      int // cc_vegas_alpha_{exit|onion}
	VegasBeta       int // cc_vegas_beta_{exit|onion}
	VegasGamma      int // cc_vegas_gamma_{exit|onion}
	VegasDelta      int // cc_vegas_delta_{exit|onion}
	SSCap           int // cc_sscap_{exit|onion}
	SSMax           int // cc_ss_max
	CwndFullGap     int // cc_cwnd_full_gap
	CwndFullMinPct  int // cc_cwnd_full_minpct
	CwndFullPerCwnd int // cc_cwnd_full_per_cwnd
	EwmaSS          int // cc_ewma_ss
	EwmaCwndPct     int // cc_ewma_cwnd_pct
	EwmaMax         int // cc_ewma_max
	RTTResetPct     int // cc_rtt_reset_pct
}

const (
	tlsRecordMaxCells = 31
	sendmeIncDefault  = tlsRecordMaxCells
	circWindowInit    = 4 * sendmeIncDefault // C Tor CIRCWINDOW_INIT
	outbufCells       = 2 * tlsRecordMaxCells
)

// DefaultCCParams 返回 C Tor 编译默认值，并叠上当前网络已写入共识的项。
// 共识未出现的键保持 C Tor 默认（例如 cc_vegas_beta_exit、cc_cwnd_init）。
func DefaultCCParams() CCParams {
	return CCParams{
		CwndInit:        circWindowInit,   // 124
		CwndMin:         circWindowInit,   // 124；2026-08 共识同值
		CwndMax:         1<<31 - 1,        // INT32_MAX
		CwndInc:         1,                // 2026-08 共识
		CwndIncRate:     sendmeIncDefault, // 31
		CwndIncPctSS:    100,
		VegasAlpha:      3 * outbufCells, // 186
		VegasBeta:       4 * outbufCells, // 248
		VegasGamma:      3 * outbufCells, // 186
		VegasDelta:      5 * outbufCells, // 310
		SSCap:           600,
		SSMax:           5000,
		CwndFullGap:     4,
		CwndFullMinPct:  25,
		CwndFullPerCwnd: 1,
		EwmaSS:          2,
		EwmaCwndPct:     50,
		EwmaMax:         10,
		RTTResetPct:     100,
	}
}

// CCParamsFromConsensus 从已验签共识 params 覆盖默认值。
// params 为 nil 时返回 DefaultCCParams。上下限对照 C Tor networkstatus_get_param。
func CCParamsFromConsensus(params map[string]int) CCParams {
	p := DefaultCCParams()
	if params == nil {
		return p
	}
	p.CwndInit = pickParam(params, "cc_cwnd_init", p.CwndInit, sendmeIncDefault, 10000)
	p.CwndMin = pickParam(params, "cc_cwnd_min", p.CwndMin, sendmeIncDefault, 1000)
	p.CwndMax = pickParam(params, "cc_cwnd_max", p.CwndMax, 500, 1<<31-1)
	p.CwndInc = pickParam(params, "cc_cwnd_inc", p.CwndInc, 1, 1000)
	p.CwndIncRate = pickParam(params, "cc_cwnd_inc_rate", p.CwndIncRate, 1, 250)
	p.CwndIncPctSS = pickParam(params, "cc_cwnd_inc_pct_ss", p.CwndIncPctSS, 1, 500)
	p.VegasAlpha = pickParam(params, "cc_vegas_alpha_exit", p.VegasAlpha, 0, 1000)
	p.VegasBeta = pickParam(params, "cc_vegas_beta_exit", p.VegasBeta, 0, 1000)
	p.VegasGamma = pickParam(params, "cc_vegas_gamma_exit", p.VegasGamma, 0, 1000)
	p.VegasDelta = pickParam(params, "cc_vegas_delta_exit", p.VegasDelta, 0, 1<<31-1)
	p.SSCap = pickParam(params, "cc_sscap_exit", p.SSCap, 100, 1<<31-1)
	p.SSMax = pickParam(params, "cc_ss_max", p.SSMax, 500, 1<<31-1)
	p.CwndFullGap = pickParam(params, "cc_cwnd_full_gap", p.CwndFullGap, 0, 32767)
	p.CwndFullMinPct = pickParam(params, "cc_cwnd_full_minpct", p.CwndFullMinPct, 0, 100)
	p.CwndFullPerCwnd = pickParam(params, "cc_cwnd_full_per_cwnd", p.CwndFullPerCwnd, 0, 1)
	p.EwmaSS = pickParam(params, "cc_ewma_ss", p.EwmaSS, 1, 100)
	p.EwmaCwndPct = pickParam(params, "cc_ewma_cwnd_pct", p.EwmaCwndPct, 1, 100)
	p.EwmaMax = pickParam(params, "cc_ewma_max", p.EwmaMax, 2, 100)
	p.RTTResetPct = pickParam(params, "cc_rtt_reset_pct", p.RTTResetPct, 0, 100)
	return p
}

// DefaultOnionCCParams 洋葱会合电路的 Vegas 缺省（C Tor *_onion / cc_sscap_onion）。
func DefaultOnionCCParams() CCParams {
	p := DefaultCCParams()
	// C Tor：alpha_onion 默认与 exit 同为 186；beta/gamma/delta/sscap 用洋葱专用值。
	p.VegasBeta = 6 * outbufCells  // 372
	p.VegasGamma = 4 * outbufCells // 248
	p.VegasDelta = 7 * outbufCells // 434
	p.SSCap = 475
	return p
}

// CCParamsOnionFromConsensus 读洋葱会合用的 Vegas / sscap 参数。
// 缺 *_onion 键时保留 DefaultOnionCCParams，不退回 exit 阈值。
func CCParamsOnionFromConsensus(params map[string]int) CCParams {
	p := DefaultOnionCCParams()
	if params == nil {
		return p
	}
	p.CwndInit = pickParam(params, "cc_cwnd_init", p.CwndInit, sendmeIncDefault, 10000)
	p.CwndMin = pickParam(params, "cc_cwnd_min", p.CwndMin, sendmeIncDefault, 1000)
	p.CwndMax = pickParam(params, "cc_cwnd_max", p.CwndMax, 500, 1<<31-1)
	p.CwndInc = pickParam(params, "cc_cwnd_inc", p.CwndInc, 1, 1000)
	p.CwndIncRate = pickParam(params, "cc_cwnd_inc_rate", p.CwndIncRate, 1, 250)
	p.CwndIncPctSS = pickParam(params, "cc_cwnd_inc_pct_ss", p.CwndIncPctSS, 1, 500)
	p.VegasAlpha = pickParam(params, "cc_vegas_alpha_onion", p.VegasAlpha, 0, 1000)
	p.VegasBeta = pickParam(params, "cc_vegas_beta_onion", p.VegasBeta, 0, 1000)
	p.VegasGamma = pickParam(params, "cc_vegas_gamma_onion", p.VegasGamma, 0, 1000)
	p.VegasDelta = pickParam(params, "cc_vegas_delta_onion", p.VegasDelta, 0, 1<<31-1)
	p.SSCap = pickParam(params, "cc_sscap_onion", p.SSCap, 100, 1<<31-1)
	p.SSMax = pickParam(params, "cc_ss_max", p.SSMax, 500, 1<<31-1)
	p.CwndFullGap = pickParam(params, "cc_cwnd_full_gap", p.CwndFullGap, 0, 32767)
	p.CwndFullMinPct = pickParam(params, "cc_cwnd_full_minpct", p.CwndFullMinPct, 0, 100)
	p.CwndFullPerCwnd = pickParam(params, "cc_cwnd_full_per_cwnd", p.CwndFullPerCwnd, 0, 1)
	p.EwmaSS = pickParam(params, "cc_ewma_ss", p.EwmaSS, 1, 100)
	p.EwmaCwndPct = pickParam(params, "cc_ewma_cwnd_pct", p.EwmaCwndPct, 1, 100)
	p.EwmaMax = pickParam(params, "cc_ewma_max", p.EwmaMax, 2, 100)
	p.RTTResetPct = pickParam(params, "cc_rtt_reset_pct", p.RTTResetPct, 0, 100)
	return p
}

// ConsensusSendmeInc 返回共识 cc_sendme_inc（缺省 31），供校验描述符 flow-control 行。
func ConsensusSendmeInc(params map[string]int) int {
	return pickParam(params, "cc_sendme_inc", sendmeIncDefault, 1, 250)
}

func pickParam(params map[string]int, key string, def, min, max int) int {
	v := def
	if p, ok := params[key]; ok {
		v = p
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
