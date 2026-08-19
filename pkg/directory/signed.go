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

	kw := "\ndirectory-signature"
	end := strings.Index(document, kw)
	if end < 0 {
		if strings.HasPrefix(document, "directory-signature") {
			end = 0
			kw = "directory-signature"
		} else {
			return nil, ErrInvalidConsensus
		}
	}

	// 包含 keyword 后的一个空格（C Tor ns_v3_offset_after_keyword）
	end += len(kw)
	if end >= len(document) || document[end] != ' ' {
		return nil, ErrInvalidConsensus
	}
	end++

	return []byte(document[start:end]), nil
}
