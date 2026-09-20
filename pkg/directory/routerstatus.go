package directory

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// MatchRelayIdentity 判断 GETINFO ns/id / desc/id 的 OR identity。
// 接受 $ 前缀的 40 位 hex、裸 hex，或共识 r 行的 identity（无 padding base64）。
func MatchRelayIdentity(r *Relay, id string) bool {
	if r == nil {
		return false
	}
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "$")
	if id == "" {
		return false
	}
	hexID := strings.ToUpper(strings.TrimPrefix(r.GetFingerprintHex(), "$"))
	if hexID != "" && strings.EqualFold(hexID, id) {
		return true
	}
	if r.Fingerprint != "" && strings.EqualFold(r.Fingerprint, id) {
		return true
	}
	raw, err := DecodeRSAIdentity(id)
	if err != nil || len(raw) != 20 || len(r.RSAIdentity) != 20 {
		return false
	}
	return bytes.Equal(raw, r.RSAIdentity)
}

// FindRelayByID 在共识中继表里找 OR identity。
func FindRelayByID(relays []*Relay, id string) *Relay {
	for _, r := range relays {
		if MatchRelayIdentity(r, id) {
			return r
		}
	}
	return nil
}

// FormatRouterStatus 按 dir-spec 写出控制器用的 router status（GETINFO ns/id）。
// 客户端用 microdesc 共识：r 行为 8 字段，digest 在 m 行，不编造 server descriptor digest。
func FormatRouterStatus(r *Relay) string {
	if r == nil {
		return ""
	}
	ident := r.Fingerprint
	if ident == "" && len(r.RSAIdentity) == 20 {
		ident = base64.RawStdEncoding.EncodeToString(r.RSAIdentity)
	}
	if ident == "" {
		ident = strings.TrimPrefix(r.GetFingerprintHex(), "$")
	}
	nick := r.Nickname
	if nick == "" {
		nick = "Unnamed"
	}
	pub := "1970-01-01 00:00:00"
	if !r.Published.IsZero() {
		pub = r.Published.UTC().Format("2006-01-02 15:04:05")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "r %s %s %s %s %d %d\n",
		nick, ident, pub, r.Address, r.ORPort, r.DirPort)
	if r.MicrodescDigest != "" {
		fmt.Fprintf(&b, "m %s\n", r.MicrodescDigest)
	}
	if r.IPv6 != "" && r.IPv6Port > 0 {
		fmt.Fprintf(&b, "a [%s]:%d\n", r.IPv6, r.IPv6Port)
	}
	if len(r.Flags) > 0 {
		fmt.Fprintf(&b, "s %s\n", strings.Join(r.Flags, " "))
	}
	fmt.Fprintf(&b, "w Bandwidth=%d\n", r.Bandwidth)
	if line := r.ExitPolicy.ControlLine("p"); line != "" {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}
