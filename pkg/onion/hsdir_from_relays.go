package onion

import (
	"fmt"

	"github.com/opd-ai/go-tor/pkg/directory"
)

// HSDirectoriesFromRelays 构造可用于 HTTP 拉取的目录节点列表。
//
// 优先：HSDir ∧ DirPort>0（负责存储的节点若开放 DirPort）。
// 补充：任意 DirPort>0 且 Running/Valid 的 V2Dir/DirCache（可缓存提供描述符）。
// 无 DirPort 的 HSDir 需 BEGIN_DIR（尚未实现），此处跳过。
func HSDirectoriesFromRelays(relays []*directory.Relay) []*HSDirectory {
	out := make([]*HSDirectory, 0)
	seen := make(map[string]struct{})
	add := func(r *directory.Relay) {
		if r == nil || r.DirPort <= 0 || !r.IsRunning() || !r.IsValid() {
			return
		}
		key := fmt.Sprintf("%s:%d", r.Address, r.DirPort)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		fp := r.GetFingerprintHex()
		if fp == "" {
			fp = r.Fingerprint
		}
		out = append(out, &HSDirectory{
			Fingerprint: fp,
			Address:     r.Address,
			ORPort:      r.ORPort,
			DirPort:     r.DirPort,
			HSDir:       r.HasFlag("HSDir"),
		})
	}
	for _, r := range relays {
		if r != nil && r.HasFlag("HSDir") {
			add(r)
		}
	}
	for _, r := range relays {
		if r != nil && (r.HasFlag("V2Dir") || r.HasFlag("DirCache") || r.DirPort > 0) {
			add(r)
		}
	}
	return out
}
