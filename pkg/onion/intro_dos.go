package onion

import (
	"encoding/binary"
)

const (
	introDoSExtType      = 0x01
	introDoSParamRate    = 0x01
	introDoSParamBurst   = 0x02
	introDoSParamValLen  = 8
	introDoSMax          = 0x7fffffff
	introDoSDefaultRate  = 25
	introDoSDefaultBurst = 200
)

// IntroDoSParams 是引言点 INTRODUCE2 令牌桶（rend-spec DOS_PARAMS / 共识 HiddenServiceEnableIntroDoS*）。
// 未宣告 HSIntro=5。
type IntroDoSParams struct {
	Defense bool
	Rate    uint64
	Burst   uint64
}

// IntroDoSExtension 是 ESTABLISH_INTRO 里解析到的第一份 DOS_PARAMS。
type IntroDoSExtension struct {
	Present bool
	Rate    uint64
	Burst   uint64
}

// IntroDoSParamsFromConsensus 读 HiddenServiceEnableIntroDoSDefense / RatePerSec / BurstPerSec。
// Defense 默认关；rate 默认 25、burst 默认 200；夹紧到 [0, 0x7fffffff]。
func IntroDoSParamsFromConsensus(params map[string]int) IntroDoSParams {
	p := IntroDoSParams{Rate: introDoSDefaultRate, Burst: introDoSDefaultBurst}
	if params == nil {
		return p
	}
	if params["HiddenServiceEnableIntroDoSDefense"] == 1 {
		p.Defense = true
	}
	if v, ok := params["HiddenServiceEnableIntroDoSRatePerSec"]; ok {
		p.Rate = clampIntroDoSValue(v)
	}
	if v, ok := params["HiddenServiceEnableIntroDoSBurstPerSec"]; ok {
		p.Burst = clampIntroDoSValue(v)
	}
	return p
}

func clampIntroDoSValue(v int) uint64 {
	if v < 0 {
		return 0
	}
	if v > introDoSMax {
		return introDoSMax
	}
	return uint64(v)
}

func clampIntroDoSUint(v uint64) uint64 {
	if v > introDoSMax {
		return introDoSMax
	}
	return v
}

// Effective 在 Defense 且 rate/burst>0 且 burst>=rate 时开启。
func (p IntroDoSParams) Effective() (enabled bool, rate, burst uint64) {
	if !p.Defense || p.Rate == 0 || p.Burst == 0 || p.Burst < p.Rate {
		return false, 0, 0
	}
	return true, p.Rate, p.Burst
}

// ResolveIntroDoS 扩展优先于共识；burst<rate 则忽略扩展。
func ResolveIntroDoS(ext IntroDoSExtension, cons IntroDoSParams) IntroDoSParams {
	if !ext.Present {
		return cons
	}
	if ext.Burst < ext.Rate {
		return cons
	}
	if ext.Rate == 0 || ext.Burst == 0 {
		return IntroDoSParams{Defense: false, Rate: ext.Rate, Burst: ext.Burst}
	}
	return IntroDoSParams{Defense: true, Rate: ext.Rate, Burst: ext.Burst}
}

func encodeIntroDoSField(rate, burst uint64) []byte {
	out := make([]byte, 1+2*(1+introDoSParamValLen))
	out[0] = 2
	out[1] = introDoSParamRate
	binary.BigEndian.PutUint64(out[2:10], clampIntroDoSUint(rate))
	out[10] = introDoSParamBurst
	binary.BigEndian.PutUint64(out[11:19], clampIntroDoSUint(burst))
	return out
}

// ParseEstablishIntroDoSExtension 读取 ESTABLISH_INTRO 中第一份 type=0x01 扩展。
func ParseEstablishIntroDoSExtension(payload []byte) IntroDoSExtension {
	if len(payload) < 36 || payload[0] != introAuthKeyTypeEd {
		return IntroDoSExtension{}
	}
	if binary.BigEndian.Uint16(payload[1:3]) != 32 {
		return IntroDoSExtension{}
	}
	off := 35
	nExt := int(payload[off])
	off++
	var out IntroDoSExtension
	for i := 0; i < nExt; i++ {
		if off+2 > len(payload) {
			return IntroDoSExtension{}
		}
		typ := payload[off]
		elen := int(payload[off+1])
		off += 2
		if off+elen > len(payload) {
			return IntroDoSExtension{}
		}
		field := payload[off : off+elen]
		off += elen
		if typ == introDoSExtType && !out.Present {
			out = parseIntroDoSField(field)
		}
	}
	return out
}

func parseIntroDoSField(field []byte) IntroDoSExtension {
	if len(field) < 1 {
		return IntroDoSExtension{}
	}
	n := int(field[0])
	off := 1
	var rate, burst uint64
	var haveRate, haveBurst bool
	for i := 0; i < n; i++ {
		if off+1+introDoSParamValLen > len(field) {
			return IntroDoSExtension{}
		}
		ptype := field[off]
		off++
		val := clampIntroDoSUint(binary.BigEndian.Uint64(field[off : off+introDoSParamValLen]))
		off += introDoSParamValLen
		switch ptype {
		case introDoSParamRate:
			if !haveRate {
				rate = val
				haveRate = true
			}
		case introDoSParamBurst:
			if !haveBurst {
				burst = val
				haveBurst = true
			}
		}
	}
	if !haveRate || !haveBurst {
		return IntroDoSExtension{}
	}
	return IntroDoSExtension{Present: true, Rate: rate, Burst: burst}
}
