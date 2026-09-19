// Package onion — 引言点候选筛选（Fast+Stable，非仅 HSDir）。
package onion

import (
	"crypto/rand"
	"math/big"

	"github.com/opd-ai/go-tor/pkg/directory"
)

// IntroPointCandidatesFromRelays 选取适合做引言点的中继（Running/Valid/Fast/Stable，有扩展密钥）。
func IntroPointCandidatesFromRelays(relays []*directory.Relay) []*HSDirectory {
	out := make([]*HSDirectory, 0, 64)
	seen := make(map[string]struct{})
	for _, r := range relays {
		if r == nil || !r.IsRunning() || !r.IsValid() || !r.HasExtendKeys() {
			continue
		}
		if !r.HasFlag("Fast") || !r.HasFlag("Stable") {
			continue
		}
		fp := r.GetFingerprintHex()
		if fp == "" {
			fp = r.Fingerprint
		}
		if fp == "" {
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, &HSDirectory{
			Fingerprint: fp,
			Address:     r.Address,
			ORPort:      r.ORPort,
			DirPort:     r.DirPort,
			Relay:       r,
		})
	}
	return out
}

// shuffleHSDirectories 打乱引言点候选，避免总用共识列表前 N 个。
func shuffleHSDirectories(in []*HSDirectory) []*HSDirectory {
	out := append([]*HSDirectory(nil), in...)
	for i := len(out) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return out
		}
		j := int(jBig.Int64())
		out[i], out[j] = out[j], out[i]
	}
	return out
}
