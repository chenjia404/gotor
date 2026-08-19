package directory

import (
	"errors"
	"strings"
)

// ErrInvalidConsensus 表示文档缺少共识签名边界。
var ErrInvalidConsensus = errors.New("invalid consensus document")

// extractConsensusSignedBody 返回所有权威共同签名的共识前缀。
//
// C Tor router_get_networkstatus_v3_signed_boundaries 把终点放在
// 第一个 "directory-signature" 关键字后的空格上，不含
// "sha256 identity signing-key"。这样每条 directory-signature
// 对应同一段 signed body。
//
// 参见 https://spec.torproject.org/dir-spec/consensus-formats.html
func extractConsensusSignedBody(document string) ([]byte, error) {
	start := strings.Index(document, "network-status-version")
	if start < 0 {
		return nil, ErrInvalidConsensus
	}

	// 只在 version 行之后找签名边界，避免 directory-signature 出现在
	// 头部之前时 start>end 切片 panic，也忽略未签名前缀里的假关键字。
	rest := document[start:]
	kw := "\ndirectory-signature"
	rel := strings.Index(rest, kw)
	if rel < 0 {
		if strings.HasPrefix(rest, "directory-signature") {
			rel = 0
			kw = "directory-signature"
		} else {
			return nil, ErrInvalidConsensus
		}
	}

	// 包含 keyword 后的一个空格（C Tor ns_v3_offset_after_keyword）
	rel += len(kw)
	if rel >= len(rest) || rest[rel] != ' ' {
		return nil, ErrInvalidConsensus
	}
	rel++

	return []byte(rest[:rel]), nil
}

// consensusSignatureSection 返回第一个 directory-signature 行起的未签名尾部。
// 权威签名本身不在 signed body 内，必须从这里解析。
func consensusSignatureSection(document string) (string, error) {
	if i := strings.Index(document, "\ndirectory-signature"); i >= 0 {
		return document[i+1:], nil
	}
	if strings.HasPrefix(document, "directory-signature") {
		return document, nil
	}
	return "", ErrInvalidConsensus
}
