// Package onion — Link Specifier 解析（tor-spec / rend-spec）。
package onion

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/opd-ai/go-tor/pkg/directory"
)

// LinkSpec types（tor-spec）
const (
	LSTypeIPv4      uint8 = 0x00
	LSTypeIPv6      uint8 = 0x01
	LSTypeLegacyID  uint8 = 0x02 // 20-byte RSA identity digest
	LSTypeEd25519ID uint8 = 0x03 // 32-byte Ed25519 identity
)

// ResolvedRelay 从 link-specifiers 解析出的可达信息。
type ResolvedRelay struct {
	IPv4        net.IP
	IPv4Port    int
	IPv6        net.IP
	IPv6Port    int
	RSAIdentity []byte // 20 bytes
	Ed25519ID   []byte // 32 bytes
}

// ParseLinkSpecifierList 解析 NSPEC || LINKSPECs 二进制。
func ParseLinkSpecifierList(data []byte) (*ResolvedRelay, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty link specifier list")
	}
	nspec := int(data[0])
	offset := 1
	out := &ResolvedRelay{}
	for i := 0; i < nspec; i++ {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated link specifier %d", i)
		}
		lstype := data[offset]
		lslen := int(data[offset+1])
		offset += 2
		if offset+lslen > len(data) {
			return nil, fmt.Errorf("truncated link specifier %d data", i)
		}
		payload := data[offset : offset+lslen]
		offset += lslen
		switch lstype {
		case LSTypeIPv4:
			if lslen != 6 {
				return nil, fmt.Errorf("IPv4 link specifier len %d", lslen)
			}
			out.IPv4 = net.IP(append([]byte(nil), payload[0:4]...))
			out.IPv4Port = int(binary.BigEndian.Uint16(payload[4:6]))
		case LSTypeIPv6:
			if lslen != 18 {
				return nil, fmt.Errorf("IPv6 link specifier len %d", lslen)
			}
			out.IPv6 = net.IP(append([]byte(nil), payload[0:16]...))
			out.IPv6Port = int(binary.BigEndian.Uint16(payload[16:18]))
		case LSTypeLegacyID:
			if lslen != 20 {
				return nil, fmt.Errorf("legacy id len %d", lslen)
			}
			out.RSAIdentity = append([]byte(nil), payload...)
		case LSTypeEd25519ID:
			if lslen != 32 {
				return nil, fmt.Errorf("ed25519 id len %d", lslen)
			}
			out.Ed25519ID = append([]byte(nil), payload...)
		default:
			// 忽略未知类型
		}
	}
	return out, nil
}

// ResolveFromIntroPoint 将引言点 link-specifiers 解析为 ResolvedRelay。
func ResolveFromIntroPoint(ip *IntroductionPoint) (*ResolvedRelay, error) {
	if ip == nil || len(ip.LinkSpecifiers) == 0 {
		return nil, fmt.Errorf("no link specifiers")
	}
	// 重新打包为 NSPEC 格式
	buf := make([]byte, 0, 128)
	buf = append(buf, byte(len(ip.LinkSpecifiers)))
	for _, ls := range ip.LinkSpecifiers {
		buf = append(buf, ls.Type, byte(len(ls.Data)))
		buf = append(buf, ls.Data...)
	}
	return ParseLinkSpecifierList(buf)
}

// MatchConsensusRelay 在共识中按 Ed25519 / RSA / 地址匹配 relay。
func MatchConsensusRelay(resolved *ResolvedRelay, relays []*directory.Relay) *directory.Relay {
	if resolved == nil {
		return nil
	}
	for _, r := range relays {
		if r == nil || !r.IsRunning() {
			continue
		}
		if len(resolved.Ed25519ID) == 32 && len(r.IdentityKey) == 32 {
			match := true
			for i := 0; i < 32; i++ {
				if resolved.Ed25519ID[i] != r.IdentityKey[i] {
					match = false
					break
				}
			}
			if match {
				return r
			}
		}
	}
	for _, r := range relays {
		if r == nil || !r.IsRunning() {
			continue
		}
		if len(resolved.RSAIdentity) == 20 && len(r.RSAIdentity) == 20 {
			match := true
			for i := 0; i < 20; i++ {
				if resolved.RSAIdentity[i] != r.RSAIdentity[i] {
					match = false
					break
				}
			}
			if match {
				return r
			}
		}
	}
	// 地址回退
	for _, r := range relays {
		if r == nil || !r.IsRunning() {
			continue
		}
		if resolved.IPv4 != nil && r.Address == resolved.IPv4.String() &&
			(resolved.IPv4Port == 0 || r.ORPort == resolved.IPv4Port) {
			return r
		}
	}
	return nil
}

// ToHSDirectory 将解析结果转为 HSDirectory（无共识匹配时用于直连信息）。
func (r *ResolvedRelay) ToHSDirectory() *HSDirectory {
	if r == nil {
		return nil
	}
	h := &HSDirectory{}
	if r.IPv4 != nil {
		h.Address = r.IPv4.String()
		h.ORPort = r.IPv4Port
	} else if r.IPv6 != nil {
		h.Address = r.IPv6.String()
		h.ORPort = r.IPv6Port
	}
	if len(r.RSAIdentity) == 20 {
		h.Fingerprint = fmt.Sprintf("%X", r.RSAIdentity)
	}
	return h
}
