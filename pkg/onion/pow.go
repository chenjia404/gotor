// 洋葱服务 v1 PoW（hspow-spec / rend-spec INTRODUCE 扩展 0x02）。
// 客户端：解析 pow-params、Equi-X 求解、Blake2b-32 工作量、写入 INTRODUCE1 内层扩展。
// 托管侧验证与控制环不在本切片。
package onion

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/crypto/equix"
	"golang.org/x/crypto/blake2b"
)

const (
	powSchemeV1    byte = 1
	introExtPoW    byte = 0x02
	powExtFieldLen      = 41
	powNonceLen         = 16
	powSeedLen          = 32
	powSolutionLen      = 16
	powPString          = "Tor hs intro v1\x00"
)

// PoWParams 来自描述符第二层明文的 pow-params v1。
type PoWParams struct {
	Seed            []byte
	SuggestedEffort uint32
	Expiration      time.Time
}

// PoWProof 是写入 INTRODUCE1 加密段的 v1 解。
type PoWProof struct {
	Nonce    [powNonceLen]byte
	Effort   uint32
	SeedHead [4]byte
	Solution [powSolutionLen]byte
}

func parsePoWParamsLine(args string) *PoWParams {
	fields := strings.Fields(args)
	if len(fields) < 4 || fields[0] != "v1" {
		return nil
	}
	seed, err := decodeDescriptorBase64(fields[1])
	if err != nil || len(seed) != powSeedLen {
		return nil
	}
	effort64, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return nil
	}
	exp, err := time.ParseInLocation("2006-01-02T15:04:05", fields[3], time.UTC)
	if err != nil {
		return nil
	}
	return &PoWParams{
		Seed:            seed,
		SuggestedEffort: uint32(effort64),
		Expiration:      exp,
	}
}

func buildPoWChallenge(blindedID, seed, nonce []byte, effort uint32) []byte {
	ch := make([]byte, 0, len(powPString)+32+powSeedLen+powNonceLen+4)
	ch = append(ch, powPString...)
	ch = append(ch, blindedID...)
	ch = append(ch, seed...)
	ch = append(ch, nonce...)
	var eb [4]byte
	binary.BigEndian.PutUint32(eb[:], effort)
	ch = append(ch, eb[:]...)
	return ch
}

func effortSatisfied(challenge, solution []byte, effort uint32) bool {
	if effort == 0 {
		return true
	}
	h, err := blake2b.New(4, nil)
	if err != nil {
		return false
	}
	_, _ = h.Write(challenge)
	_, _ = h.Write(solution)
	r := binary.BigEndian.Uint32(h.Sum(nil))
	return uint64(r)*uint64(effort) <= uint64(^uint32(0))
}

func incrementNonce(n *[powNonceLen]byte) {
	for i := 0; i < powNonceLen; i++ {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// SolveOnionPoW 按 hspow-spec v1 求解。suggested-effort 为 0 时不求解。
func SolveOnionPoW(ctx context.Context, params *PoWParams, blindedID []byte) (*PoWProof, error) {
	if params == nil {
		return nil, nil
	}
	if len(params.Seed) != powSeedLen {
		return nil, fmt.Errorf("pow seed 长度必须为 32")
	}
	if len(blindedID) != 32 {
		return nil, fmt.Errorf("致盲公钥必须为 32 字节")
	}
	if !params.Expiration.IsZero() && time.Now().UTC().After(params.Expiration) {
		return nil, fmt.Errorf("pow-params 种子已过期")
	}
	if params.SuggestedEffort == 0 {
		return nil, nil
	}

	var nonce [powNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("pow nonce: %w", err)
	}
	effort := params.SuggestedEffort
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("pow 求解取消: %w", err)
		}
		ch := buildPoWChallenge(blindedID, params.Seed, nonce[:], effort)
		eq, err := equix.New(ch)
		if err != nil {
			incrementNonce(&nonce)
			continue
		}
		for _, sol := range eq.Solve() {
			sb := sol.Bytes()
			if !effortSatisfied(ch, sb[:], effort) {
				continue
			}
			proof := &PoWProof{Effort: effort}
			copy(proof.Nonce[:], nonce[:])
			copy(proof.SeedHead[:], params.Seed[:4])
			copy(proof.Solution[:], sb[:])
			return proof, nil
		}
		incrementNonce(&nonce)
	}
}

func encodePoWExtension(p *PoWProof) []byte {
	ext := make([]byte, 2+powExtFieldLen)
	ext[0] = introExtPoW
	ext[1] = powExtFieldLen
	ext[2] = powSchemeV1
	copy(ext[3:19], p.Nonce[:])
	binary.BigEndian.PutUint32(ext[19:23], p.Effort)
	copy(ext[23:27], p.SeedHead[:])
	copy(ext[27:43], p.Solution[:])
	return ext
}
