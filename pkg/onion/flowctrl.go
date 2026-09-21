package onion

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	introExtCCRequest byte = 0x01 // rend-spec INTRODUCE 加密段：CC_FIELD_REQUEST（零长度）
)

// FlowControlParams 来自描述符第二层明文的 flow-control 行（prop324 / rend-spec）。
type FlowControlParams struct {
	VersionMin int
	VersionMax int
	SendmeInc  int
}

// SupportsFlowCtrl2 表示描述符宣告可用 FlowCtrl=2。
func (p *FlowControlParams) SupportsFlowCtrl2() bool {
	return p != nil && p.VersionMin <= 2 && p.VersionMax >= 2 && p.SendmeInc >= 1 && p.SendmeInc <= 250
}

// parseFlowControlLine 解析 "1-2 31" 形式（keyword 已剥掉）。
func parseFlowControlLine(args string) *FlowControlParams {
	fields := strings.Fields(args)
	if len(fields) < 2 {
		return nil
	}
	lo, hi, ok := strings.Cut(fields[0], "-")
	if !ok {
		return nil
	}
	vmin, err1 := strconv.Atoi(lo)
	vmax, err2 := strconv.Atoi(hi)
	inc, err3 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil
	}
	if vmin < 1 || vmax < vmin || vmax > 255 || inc < 1 || inc > 250 {
		return nil
	}
	return &FlowControlParams{VersionMin: vmin, VersionMax: vmax, SendmeInc: inc}
}

// sendmeIncCompatible 对照 prop324：描述符 sendme-inc 须在共识 cc_sendme_inc 的 2 倍以内。
func sendmeIncCompatible(descInc, consensusInc int) bool {
	if descInc < 1 || consensusInc < 1 {
		return false
	}
	if descInc == consensusInc {
		return true
	}
	lo, hi := consensusInc, descInc
	if lo > hi {
		lo, hi = hi, lo
	}
	return hi <= 2*lo
}

func encodeCCRequestExtension() []byte {
	return []byte{introExtCCRequest, 0}
}

func validateFlowControlForRequest(fc *FlowControlParams, ccAlg, consensusInc int) error {
	if fc == nil || !fc.SupportsFlowCtrl2() {
		return fmt.Errorf("descriptor missing FlowCtrl=2")
	}
	if ccAlg == 0 {
		return fmt.Errorf("consensus cc_alg=0")
	}
	if !sendmeIncCompatible(fc.SendmeInc, consensusInc) {
		return fmt.Errorf("sendme-inc %d incompatible with consensus %d", fc.SendmeInc, consensusInc)
	}
	return nil
}
