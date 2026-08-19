package onion

import (
	"fmt"

	"github.com/opd-ai/go-tor/pkg/directory"
)

// HSDirectoriesFromRelays 构造 HS 目录节点列表。
//
// - 所有 Running/Valid 的 HSDir（含 DirPort=0，供 BEGIN_DIR）
// - 另加入 DirPort>0 的 V2Dir/DirCache（HTTP 回退）
// Relay 字段指向共识条目，便于 BEGIN_DIR 取 ntor 密钥。
func HSDirectoriesFromRelays(relays []*directory.Relay) []*HSDirectory {
	out := make([]*HSDirectory, 0)
	seen := make(map[string]struct{})
	add := func(r *directory.Relay, requireDirPort bool) {
		if r == nil || !r.IsRunning() || !r.IsValid() {
			return
		}
		if requireDirPort && r.DirPort <= 0 {
			return
		}
		fp := r.GetFingerprintHex()
		if fp == "" {
			fp = r.Fingerprint
		}
		key := fp
		if key == "" {
			key = fmt.Sprintf("%s:%d:%d", r.Address, r.ORPort, r.DirPort)
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, &HSDirectory{
			Fingerprint: fp,
			Address:     r.Address,
			ORPort:      r.ORPort,
			DirPort:     r.DirPort,
			HSDir:       r.HasFlag("HSDir"),
			Relay:       r,
		})
	}
	for _, r := range relays {
		if r != nil && r.HasFlag("HSDir") {
			add(r, false)
		}
	}
	for _, r := range relays {
		if r != nil && r.DirPort > 0 {
			add(r, true)
		}
	}
	return out
}
