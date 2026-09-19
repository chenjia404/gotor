package directory

import (
	"strings"
)

// ConsensusFlavor 是 dir-spec 共识文档的 flavor。
// ns 与 microdesc 不得混库存放或互相当成对方对外服务。
type ConsensusFlavor string

const (
	// FlavorNS 对应 GET /tor/status-vote/current/consensus（无 flavor 后缀）。
	FlavorNS ConsensusFlavor = "ns"
	// FlavorMicrodesc 对应 GET /tor/status-vote/current/consensus-microdesc。
	FlavorMicrodesc ConsensusFlavor = "microdesc"
)

const (
	cachedNSConsensusName     = "cached-consensus"
	cachedNSConsensusPrevName = "cached-consensus.prev"
	// CachedNSConsensusHistDir 存放 ns flavor 历史共识（按 FromDigest 命名）。
	CachedNSConsensusHistDir = "cached-consensus.hist"
)

// ConsensusCacheFile 返回该 flavor 在 CacheDirectory 下的当前共识文件名。
func ConsensusCacheFile(f ConsensusFlavor) string {
	if f == FlavorNS {
		return cachedNSConsensusName
	}
	return cachedMicrodescConsensusName
}

// ConsensusCachePrevFile 返回该 flavor 的 .prev 文件名。
func ConsensusCachePrevFile(f ConsensusFlavor) string {
	return consensusPrevFile(f)
}

func consensusPrevFile(f ConsensusFlavor) string {
	if f == FlavorNS {
		return cachedNSConsensusPrevName
	}
	return cachedMicrodescConsensusPrevName
}

func consensusHistDir(f ConsensusFlavor) string {
	if f == FlavorNS {
		return CachedNSConsensusHistDir
	}
	return CachedMicrodescConsensusHistDir
}

// DetectConsensusFlavor 读首个 network-status-version 行。
// dir-spec：`network-status-version` SP version [SP flavor]；缺 flavor 即为 ns。
func DetectConsensusFlavor(doc string) (ConsensusFlavor, bool) {
	doc = stripConsensusPreamble(doc)
	line, _, _ := strings.Cut(doc, "\n")
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "network-status-version ") {
		return "", false
	}
	fields := strings.Fields(line)
	// network-status-version <ver> [flavor]
	if len(fields) < 2 {
		return "", false
	}
	if len(fields) >= 3 && fields[2] == "microdesc" {
		return FlavorMicrodesc, true
	}
	return FlavorNS, true
}

// ConsensusFlavorFromHTTPPath 从 DirPort / BEGIN_DIR 路径判断请求的 flavor。
// 必须先匹配 consensus-microdesc，避免子串误判。
func ConsensusFlavorFromHTTPPath(path string) (ConsensusFlavor, bool) {
	path = strings.TrimSuffix(path, ".z")
	switch {
	case strings.Contains(path, "/consensus-microdesc"):
		return FlavorMicrodesc, true
	case strings.Contains(path, "/consensus/") || strings.HasSuffix(path, "/consensus"):
		return FlavorNS, true
	default:
		return "", false
	}
}

// NSConsensusURL 把权威 microdesc 共识 URL 转成 ns flavor URL。
func NSConsensusURL(authorityURL string) string {
	u := strings.TrimSuffix(authorityURL, "/tor/status-vote/current/consensus-microdesc")
	u = strings.TrimSuffix(u, "/tor/status-vote/current/consensus")
	u = strings.TrimRight(u, "/")
	return u + "/tor/status-vote/current/consensus"
}
