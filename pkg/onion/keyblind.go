// Package onion — Ed25519 KEYBLIND（rend-spec-v3 Appendix A）。
//
// 对照 C Tor hs_common.c build_blinded_key_param + ed25519_ref10_blind_public_key。
package onion

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"time"

	"filippo.io/edwards25519"
)

const (
	// hsdirIntervalDefaultMinutes 默认 hsdir_interval（分钟）。
	hsdirIntervalDefaultMinutes = 1440
	// hsdirRotationOffsetMinutes 默认与 SRV 对齐的旋转偏移（12 小时）。
	hsdirRotationOffsetMinutes = 12 * 60
)

// ed25519BasepointString 与 C Tor str_ed25519_basepoint 完全一致（含逗号后空格）。
const ed25519BasepointString = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

// BuildBlindedKeyParam 构造致盲参数 h（未 clamp），可选 secret s。
//
//	N = "key-blind" || INT_8(period_num) || INT_8(period_length)
//	h = SHA3_256("Derive temporary signing key" || 0x00 || A || [s] || basepoint_str || N)
func BuildBlindedKeyParam(pubkey []byte, secret []byte, periodNum, periodLength uint64) ([]byte, error) {
	if len(pubkey) != 32 {
		return nil, fmt.Errorf("pubkey must be 32 bytes")
	}
	nonce := make([]byte, 0, 8+8+8)
	nonce = append(nonce, []byte("key-blind")...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], periodNum)
	nonce = append(nonce, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], periodLength)
	nonce = append(nonce, tmp[:]...)

	h := sha3.New256()
	// sizeof("Derive temporary signing key") in C includes NUL
	// lgtm[go/weak-sensitive-data-hashing] KEYBLIND 按 rend-spec-v3 使用 SHA3-256 致盲公钥，非口令哈希
	_, _ = h.Write([]byte("Derive temporary signing key\x00"))
	_, _ = h.Write(pubkey)
	if len(secret) > 0 {
		_, _ = h.Write(secret)
	}
	_, _ = h.Write([]byte(ed25519BasepointString))
	_, _ = h.Write(nonce)
	return h.Sum(nil), nil
}

func clampBlindingFactor(h []byte) []byte {
	out := make([]byte, 32)
	copy(out, h)
	out[0] &= 248
	out[31] &= 63
	out[31] |= 64
	return out
}

// ComputeBlindedPubkey 按 KEYBLIND 计算周期致盲公钥 A' = h·A。
// periodLengthMinutes 为 0 时使用默认 1440。
func ComputeBlindedPubkey(pubkey ed25519.PublicKey, timePeriod uint64) []byte {
	return ComputeBlindedPubkeyWithLength(pubkey, timePeriod, hsdirIntervalDefaultMinutes)
}

// ComputeBlindedPubkeyWithLength 允许指定 period_length（分钟）。
func ComputeBlindedPubkeyWithLength(pubkey ed25519.PublicKey, timePeriod, periodLengthMinutes uint64) []byte {
	if periodLengthMinutes == 0 {
		periodLengthMinutes = hsdirIntervalDefaultMinutes
	}
	param, err := BuildBlindedKeyParam([]byte(pubkey), nil, timePeriod, periodLengthMinutes)
	if err != nil {
		out := make([]byte, 32)
		return out
	}
	// C Tor gettweak：复制 param 后 clamp，再作标量。SetBytesWithClamping 等价。
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(param)
	if err != nil {
		out := make([]byte, 32)
		return out
	}
	A, err := new(edwards25519.Point).SetBytes([]byte(pubkey))
	if err != nil {
		out := make([]byte, 32)
		return out
	}
	Aprime := new(edwards25519.Point).ScalarMult(s, A)
	return Aprime.Bytes()
}

// GetTimePeriod 计算当前 HS 时间周期号（与 C Tor hs_get_time_period_num 一致）。
//
//	minutes = unix/60 - rotation_offset
//	period  = minutes / hsdir_interval
func GetTimePeriod(now time.Time) uint64 {
	return GetTimePeriodWithParams(now, hsdirIntervalDefaultMinutes, hsdirRotationOffsetMinutes)
}

// GetTimePeriodWithParams 允许覆盖 interval / offset（分钟）。
func GetTimePeriodWithParams(now time.Time, intervalMin, offsetMin uint64) uint64 {
	if intervalMin == 0 {
		intervalMin = hsdirIntervalDefaultMinutes
	}
	unix := now.Unix()
	if unix < 0 {
		return 0
	}
	minutes := uint64(unix) / 60
	if minutes < offsetMin {
		return 0
	}
	minutes -= offsetMin
	return minutes / intervalMin
}
