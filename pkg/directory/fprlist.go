package directory

import (
	"strings"
)

const (
	maxFPRLISTItems = 16
	minFPHexLen     = 2
	maxFPHexLen     = 40
)

// ParseFPRLIST 解析共识 URL 里的 + 分隔权威身份指纹。
// 空或 "all" 表示不筛选。非法 token 返回 ok=false。
func ParseFPRLIST(raw string) (fps []string, filter bool, ok bool) {
	raw = strings.Trim(raw, "/")
	if raw == "" || strings.EqualFold(raw, "all") {
		return nil, false, true
	}
	if strings.Contains(raw, "..") {
		return nil, false, false
	}
	parts := strings.Split(raw, "+")
	if len(parts) == 0 || len(parts) > maxFPRLISTItems {
		return nil, false, false
	}
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if !validFPToken(p) {
			return nil, false, false
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, false, false
	}
	return out, true, true
}

func validFPToken(p string) bool {
	n := len(p)
	if n < minFPHexLen || n > maxFPHexLen || n%2 != 0 {
		return false
	}
	for i := 0; i < n; i++ {
		c := p[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// FPRLISTHasMajority 对照 dir-spec：须超过半数被请求权威已签名。
func FPRLISTHasMajority(requested, matched int) bool {
	if requested <= 0 {
		return true
	}
	return matched*2 > requested
}

// FilterConsensusByFPRLIST 只保留 identity 匹配 fps 的 directory-signature 块。
// fps 为空则原样返回。ok=false 表示文档没有签名边界。
func FilterConsensusByFPRLIST(doc string, fps []string) (out string, matched int, ok bool) {
	if len(fps) == 0 {
		return doc, 0, true
	}
	head, sigs, ok := splitConsensusSignatures(doc)
	if !ok {
		return "", 0, false
	}
	hit := make([]bool, len(fps))
	var kept strings.Builder
	for _, block := range sigs {
		id, ok := signatureIdentity(block)
		if !ok {
			continue
		}
		id = strings.ToLower(id)
		keep := false
		for i, fp := range fps {
			if strings.HasPrefix(id, fp) {
				hit[i] = true
				keep = true
			}
		}
		if keep {
			kept.WriteString(block)
		}
	}
	for _, h := range hit {
		if h {
			matched++
		}
	}
	return head + kept.String(), matched, true
}

func splitConsensusSignatures(doc string) (head string, blocks []string, ok bool) {
	var starts []int
	if strings.HasPrefix(doc, "directory-signature ") {
		starts = append(starts, 0)
	}
	search, off := doc, 0
	for {
		i := strings.Index(search, "\ndirectory-signature ")
		if i < 0 {
			break
		}
		starts = append(starts, off+i+1)
		search = search[i+1:]
		off += i + 1
	}
	if len(starts) == 0 {
		return "", nil, false
	}
	head = doc[:starts[0]]
	for i, s := range starts {
		end := len(doc)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		blocks = append(blocks, doc[s:end])
	}
	return head, blocks, true
}

func signatureIdentity(block string) (string, bool) {
	line := block
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	parts := strings.Fields(line)
	switch {
	case len(parts) == 3:
		return parts[1], true
	case len(parts) >= 4:
		return parts[2], true
	default:
		return "", false
	}
}
