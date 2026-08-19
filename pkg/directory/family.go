package directory

import (
	"bytes"
	"strings"
)

// FamilyPolicyFromParams 读共识 params。缺省与最新 Tor 一致：两者都启用。
func FamilyPolicyFromParams(params map[string]int) (useIDs, useLists bool) {
	useIDs, useLists = true, true
	if params == nil {
		return
	}
	if v, ok := params["use-family-ids"]; ok {
		useIDs = v != 0
	}
	if v, ok := params["use-family-lists"]; ok {
		useLists = v != 0
	}
	return
}

func (r *Relay) InSameFamily(other *Relay) bool {
	return r.InSameFamilyPolicy(other, true, true)
}

// InSameFamilyPolicy 对照 path-spec determining-family-membership：
//   - useIDs：共享任一 family-ids 即为同家族（无需双向声明）
//   - useLists：旧 family 列表必须双向列出对方
func (r *Relay) InSameFamilyPolicy(other *Relay, useIDs, useLists bool) bool {
	if r == nil || other == nil {
		return false
	}
	if sameRelayIdentity(r, other) {
		return true
	}
	if useIDs && shareFamilyID(r.FamilyIDs, other.FamilyIDs) {
		return true
	}
	if useLists && familyListsBidirectional(r, other) {
		return true
	}
	return false
}

func sameRelayIdentity(a, b *Relay) bool {
	if a == b {
		return true
	}
	if hx := a.GetFingerprintHex(); hx != "" && hx == b.GetFingerprintHex() {
		return true
	}
	if a.Fingerprint != "" && a.Fingerprint == b.Fingerprint {
		return true
	}
	if len(a.RSAIdentity) == 20 && len(b.RSAIdentity) == 20 &&
		bytes.Equal(a.RSAIdentity, b.RSAIdentity) {
		return true
	}
	if len(a.IdentityKey) == 32 && len(b.IdentityKey) == 32 &&
		bytes.Equal(a.IdentityKey, b.IdentityKey) {
		return true
	}
	return false
}

func shareFamilyID(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, id := range a {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		seen[id] = struct{}{}
	}
	if len(seen) == 0 {
		return false
	}
	for _, id := range b {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			return true
		}
	}
	return false
}

func familyListsBidirectional(a, b *Relay) bool {
	return familyListContains(a.Family, b) && familyListContains(b.Family, a)
}

func familyListContains(list []string, other *Relay) bool {
	if other == nil || len(list) == 0 {
		return false
	}
	hex := strings.ToUpper(strings.TrimPrefix(other.GetFingerprintHex(), "$"))
	fp := other.Fingerprint
	fpUpper := strings.ToUpper(strings.TrimPrefix(fp, "$"))
	nick := strings.ToLower(other.Nickname)

	for _, raw := range list {
		m := strings.TrimSpace(raw)
		if m == "" {
			continue
		}
		if fp != "" && m == fp {
			return true
		}
		if other.FingerprintHex != "" && m == other.FingerprintHex {
			return true
		}
		if nick != "" && strings.ToLower(m) == nick {
			return true
		}
		token := familyListToken(m)
		if token == "" {
			continue
		}
		if hex != "" && token == hex {
			return true
		}
		if fpUpper != "" && token == fpUpper {
			return true
		}
	}
	return false
}

// familyListToken 规范化 $HEX[=name|~name]；无法识别则返回大写原文供短测试向量匹配。
func familyListToken(m string) string {
	m = strings.TrimSpace(m)
	if strings.HasPrefix(m, "$") {
		m = m[1:]
	}
	if i := strings.IndexAny(m, "=~"); i >= 0 {
		m = m[:i]
	}
	return strings.ToUpper(m)
}

func parseFamilyIDs(fields []string) []string {
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, id := range fields {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
