package directory

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// C Tor consdiff.c MAX_LINE_COUNT：对齐身份后单块超过此行数则拒绝生成。
const maxEdChunkLines = 10000

// GenerateConsensusDiff 生成 limited-ed 共识差分（dir-spec / C Tor consdiff_gen_diff）。
//
//   - FromDigest = 旧文档 signed part 的 SHA3-256
//   - ToDigest   = 新文档整份（含签名）的 SHA3-256
//   - 旧文档含 directory-signature 时，第一条命令必须是「首个签名行,$d」
//   - 其余 d/c/a 按身份对齐的 r 行分块，再对块做 LCS；命令从后往前
//
// 成功后用 applyConsensusDiff 自检；失败不返回半成品。
func GenerateConsensusDiff(oldDoc, newDoc string) (string, error) {
	oldDoc = stripConsensusPreamble(strings.TrimPrefix(oldDoc, "\ufeff"))
	newDoc = stripConsensusPreamble(strings.TrimPrefix(newDoc, "\ufeff"))
	oldNorm := normalizeConsensusText(oldDoc)
	newNorm := normalizeConsensusText(newDoc)
	if strings.TrimSpace(oldNorm) == "" || strings.TrimSpace(newNorm) == "" {
		return "", fmt.Errorf("consensus diff: empty document")
	}
	oldLines := splitConsensusLines(oldNorm)
	newLines := splitConsensusLines(newNorm)
	if err := checkConsensusLineLengths(oldLines); err != nil {
		return "", err
	}
	if err := checkConsensusLineLengths(newLines); err != nil {
		return "", err
	}
	if len(oldLines) > maxConsensusDiffLines || len(newLines) > maxConsensusDiffLines {
		return "", fmt.Errorf("consensus too large to diff")
	}

	cmds, err := genEdDiff(oldLines, newLines)
	if err != nil {
		return "", err
	}

	from := consensusDiffFromDigest(oldNorm)
	to := sha3_256Hex([]byte(newNorm))

	var b strings.Builder
	b.Grow(256 + len(newNorm)/8)
	b.WriteString("network-status-diff-version 1\n")
	b.WriteString("hash ")
	b.WriteString(from)
	b.WriteByte(' ')
	b.WriteString(to)
	b.WriteByte('\n')
	for i := range cmds {
		if err := writeEdCommand(&b, cmds[i]); err != nil {
			return "", err
		}
	}
	diff := b.String()

	got, err := applyConsensusDiff(oldNorm, diff)
	if err != nil {
		return "", fmt.Errorf("generated consensus diff failed self-apply: %w", err)
	}
	if got != newNorm {
		return "", fmt.Errorf("generated consensus diff self-apply mismatch")
	}
	return diff, nil
}

// ParseOrDiffFromConsensusHeader 解析 X-Or-Diff-From-Consensus。
// dir-spec 用逗号分隔；proposal 140 / 部分实现用空白。两者都接受。
func ParseOrDiffFromConsensusHeader(h string) []string {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil
	}
	h = strings.ReplaceAll(h, ",", " ")
	var out []string
	seen := make(map[string]struct{}, 4)
	for _, p := range strings.Fields(h) {
		p = strings.ToLower(strings.TrimSpace(p))
		if !validSHA3Hex(p) {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func genEdDiff(oldOrig, newLines []string) ([]edCommand, error) {
	oldLines := append([]string(nil), oldOrig...)
	var cmds []edCommand

	if sig := firstDirectorySignatureLine(oldLines); sig > 0 {
		cmds = append(cmds, edCommand{op: 'd', n1: sig, endToEOF: true})
		oldLines = oldLines[:sig-1]
	}

	changed1, changed2, err := markConsensusChanges(oldLines, newLines)
	if err != nil {
		return nil, err
	}
	body, err := commandsFromChanges(oldLines, newLines, changed1, changed2)
	if err != nil {
		return nil, err
	}
	return append(cmds, body...), nil
}

type routerSpan struct {
	id    string
	start int // 含
	end   int // 不含
}

func markConsensusChanges(oldL, newL []string) ([]bool, []bool, error) {
	c1 := make([]bool, len(oldL))
	c2 := make([]bool, len(newL))
	oldH, oldR, oldF := splitRouterSpans(oldL)
	newH, newR, newF := splitRouterSpans(newL)

	if !routerSpansSorted(oldR) || !routerSpansSorted(newR) {
		if err := markLineChangesRange(oldL, newL, 0, len(oldL), 0, len(newL), c1, c2); err != nil {
			return nil, nil, err
		}
		return c1, c2, nil
	}

	if err := markLineChangesRange(oldL, newL, 0, oldH, 0, newH, c1, c2); err != nil {
		return nil, nil, err
	}

	i, j := 0, 0
	for i < len(oldR) || j < len(newR) {
		if i < len(oldR) && j < len(newR) {
			cmp := cmpIdentityString(oldR[i].id, newR[j].id)
			switch {
			case cmp == 0:
				if err := markLineChangesRange(oldL, newL, oldR[i].start, oldR[i].end, newR[j].start, newR[j].end, c1, c2); err != nil {
					return nil, nil, err
				}
				i++
				j++
			case cmp < 0:
				markSpanChanged(c1, oldR[i].start, oldR[i].end)
				i++
			default:
				markSpanChanged(c2, newR[j].start, newR[j].end)
				j++
			}
			continue
		}
		if i < len(oldR) {
			markSpanChanged(c1, oldR[i].start, oldR[i].end)
			i++
			continue
		}
		markSpanChanged(c2, newR[j].start, newR[j].end)
		j++
	}

	if err := markLineChangesRange(oldL, newL, oldF, len(oldL), newF, len(newL), c1, c2); err != nil {
		return nil, nil, err
	}
	return c1, c2, nil
}

func splitRouterSpans(lines []string) (headerEnd int, routers []routerSpan, footerStart int) {
	idx := routerLineIndices(lines)
	if len(idx) == 0 {
		return len(lines), nil, len(lines)
	}
	headerEnd = idx[0]
	footerStart = len(lines)
	for i, ridx := range idx {
		id, _ := routerIdentityField(lines[ridx])
		end := len(lines)
		if i+1 < len(idx) {
			end = idx[i+1]
		} else {
			end = findConsensusFooter(lines, ridx+1)
			footerStart = end
		}
		routers = append(routers, routerSpan{id: id, start: ridx, end: end})
	}
	return headerEnd, routers, footerStart
}

func findConsensusFooter(lines []string, from int) int {
	for i := from; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "directory-footer") || strings.HasPrefix(lines[i], "directory-signature ") {
			return i
		}
	}
	return len(lines)
}

func markSpanChanged(changed []bool, start, end int) {
	for i := start; i < end && i < len(changed); i++ {
		changed[i] = true
	}
}

func routerSpansSorted(spans []routerSpan) bool {
	var prev []byte
	for _, s := range spans {
		raw, err := decodeRouterIdentity(s.id)
		if err != nil {
			return false
		}
		if prev != nil && bytesCompareUnsigned(raw, prev) <= 0 {
			return false
		}
		prev = raw
	}
	return true
}

func cmpIdentityString(a, b string) int {
	ra, errA := decodeRouterIdentity(a)
	rb, errB := decodeRouterIdentity(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	return bytesCompareUnsigned(ra, rb)
}

func markLineChangesRange(a, b []string, a0, a1, b0, b1 int, ca, cb []bool) error {
	if a0 < 0 || b0 < 0 || a1 < a0 || b1 < b0 || a1 > len(a) || b1 > len(b) {
		return fmt.Errorf("consensus diff: invalid slice")
	}
	for a0 < a1 && b0 < b1 && a[a0] == b[b0] {
		a0++
		b0++
	}
	for a1 > a0 && b1 > b0 && a[a1-1] == b[b1-1] {
		a1--
		b1--
	}
	if a0 >= a1 && b0 >= b1 {
		return nil
	}
	subA, subB := a[a0:a1], b[b0:b1]
	if len(subA) <= 1 || len(subB) <= 1 {
		for i := a0; i < a1; i++ {
			ca[i] = true
		}
		for i := b0; i < b1; i++ {
			cb[i] = true
		}
		return nil
	}
	if len(subA) > maxEdChunkLines || len(subB) > maxEdChunkLines {
		return fmt.Errorf("consensus diff chunk too large")
	}
	// 未对齐的整篇 LCS 可能到数万行；超过此格数则整块标为变更（仍是合法 limited-ed）。
	const maxLCSCells = 2_000_000
	if len(subA)*len(subB) > maxLCSCells {
		for i := a0; i < a1; i++ {
			ca[i] = true
		}
		for i := b0; i < b1; i++ {
			cb[i] = true
		}
		return nil
	}
	keepA, keepB := lcsKeep(subA, subB)
	for i, keep := range keepA {
		if !keep {
			ca[a0+i] = true
		}
	}
	for i, keep := range keepB {
		if !keep {
			cb[b0+i] = true
		}
	}
	return nil
}

func lcsKeep(a, b []string) (keepA, keepB []bool) {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			if a[i] == b[j] {
				dp[i+1][j+1] = dp[i][j] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i+1][j+1] = dp[i+1][j]
			} else {
				dp[i+1][j+1] = dp[i][j+1]
			}
		}
	}
	keepA = make([]bool, n)
	keepB = make([]bool, m)
	i, j := n, m
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] && dp[i][j] == dp[i-1][j-1]+1 {
			keepA[i-1] = true
			keepB[j-1] = true
			i--
			j--
		} else if dp[i-1][j] >= dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	return keepA, keepB
}

func commandsFromChanges(oldL, newL []string, c1, c2 []bool) ([]edCommand, error) {
	var cmds []edCommand
	i1, i2 := len(oldL)-1, len(newL)-1
	for i1 >= 0 || i2 >= 0 {
		ch1 := i1 >= 0 && c1[i1]
		ch2 := i2 >= 0 && c2[i2]
		if !ch1 && !ch2 {
			if i1 >= 0 {
				i1--
			}
			if i2 >= 0 {
				i2--
			}
			continue
		}
		end1, end2 := i1, i2
		for i1 >= 0 && c1[i1] {
			i1--
		}
		for i2 >= 0 && c2[i2] {
			i2--
		}
		start1 := i1 + 1
		start2 := i2 + 1
		deleted := end1 - i1
		added := end2 - i2
		if added == 0 {
			n1 := start1 + 1
			n2 := start1 + deleted
			cmds = append(cmds, edCommand{op: 'd', n1: n1, n2: n2})
			continue
		}
		block := append([]string(nil), newL[start2:end2+1]...)
		if err := rejectDotOnlyLines(block); err != nil {
			return nil, err
		}
		if deleted == 0 {
			// start1 是 0 基「将要删除的第一行」= 1 基「最后未改行」，即 a 的行号（可为 0）。
			cmds = append(cmds, edCommand{op: 'a', n1: start1, n2: start1, block: block})
			continue
		}
		n1 := start1 + 1
		n2 := start1 + deleted
		cmds = append(cmds, edCommand{op: 'c', n1: n1, n2: n2, block: block})
	}
	return cmds, nil
}

func writeEdCommand(b *strings.Builder, cmd edCommand) error {
	switch cmd.op {
	case 'd':
		if cmd.endToEOF {
			fmt.Fprintf(b, "%d,$d\n", cmd.n1)
			return nil
		}
		if cmd.n1 == cmd.n2 {
			fmt.Fprintf(b, "%dd\n", cmd.n1)
			return nil
		}
		fmt.Fprintf(b, "%d,%dd\n", cmd.n1, cmd.n2)
		return nil
	case 'c':
		if cmd.n1 == cmd.n2 {
			fmt.Fprintf(b, "%dc\n", cmd.n1)
		} else {
			fmt.Fprintf(b, "%d,%dc\n", cmd.n1, cmd.n2)
		}
		return writeEdBlock(b, cmd.block)
	case 'a':
		fmt.Fprintf(b, "%da\n", cmd.n1)
		return writeEdBlock(b, cmd.block)
	default:
		return fmt.Errorf("unsupported ed command")
	}
}

func writeEdBlock(b *strings.Builder, block []string) error {
	if len(block) == 0 {
		return fmt.Errorf("ed command inserts zero lines")
	}
	if err := rejectDotOnlyLines(block); err != nil {
		return err
	}
	for _, line := range block {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(".\n")
	return nil
}

func rejectDotOnlyLines(block []string) error {
	for _, line := range block {
		if line == "." || strings.TrimRight(line, " \t") == "." {
			return fmt.Errorf("cannot insert a line that is only a dot")
		}
	}
	return nil
}

func routerIdentityField(line string) (string, bool) {
	if !strings.HasPrefix(line, "r ") {
		return "", false
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", false
	}
	id := fields[2]
	if id == "" {
		return "", false
	}
	return id, true
}

func routerLineIndices(lines []string) []int {
	idx := make([]int, 0, 8)
	for i, line := range lines {
		if _, ok := routerIdentityField(line); ok {
			idx = append(idx, i)
		}
	}
	return idx
}

func decodeRouterIdentity(s string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("invalid router identity")
	}
	return raw, nil
}

func bytesCompareUnsigned(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}
