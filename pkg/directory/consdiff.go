package directory

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	consensusDiffVersion     = "1"
	maxConsensusDiffLines    = 200000
	maxConsensusDiffCommands = 100000
	maxConsensusLineBytes    = 1 << 20 // 与 C Tor CONSENSUS_LINE_MAX_LEN 一致
	maxEdCommandBytes        = 128     // 与 C Tor apply_ed_diff 命令行缓冲一致
)

// applyConsensusDiff 把 limited ed 共识 diff 应用到已缓存的整份共识。
//
// 对照 dir-spec directory-cache-operation / limited-ed-diff-format：
//   - 第一行 network-status-diff-version 1
//   - 第二行 hash FromDigest ToDigest（SHA3-256 十六进制）
//   - FromDigest = 旧文档 signed part 的 SHA3-256（与 extractConsensusSignedBody 一致）
//   - ToDigest   = 应用后整份新共识（含签名）的 SHA3-256
//   - 只接受 d / c / a；有 directory-signature 时第一条必须是「首个签名行,$d」
func applyConsensusDiff(oldDoc, diffDoc string) (string, error) {
	oldDoc = stripConsensusPreamble(strings.TrimPrefix(oldDoc, "\ufeff"))
	from, to, commands, err := parseConsensusDiff(diffDoc)
	if err != nil {
		return "", err
	}
	gotFrom := consensusDiffFromDigest(oldDoc)
	if !hexDigestEqual(gotFrom, from) {
		return "", fmt.Errorf("consensus diff FromDigest mismatch")
	}
	lines := splitConsensusLines(oldDoc)
	if err := checkConsensusLineLengths(lines); err != nil {
		return "", err
	}
	if len(lines) > maxConsensusDiffLines {
		return "", fmt.Errorf("cached consensus too large")
	}
	if sigLine := firstDirectorySignatureLine(lines); sigLine > 0 {
		if len(commands) == 0 || commands[0].op != 'd' || !commands[0].endToEOF || commands[0].n1 != sigLine {
			return "", fmt.Errorf("first consensus diff command must be %d,$d", sigLine)
		}
	}
	if err := checkEdReverseOrder(commands, len(lines)); err != nil {
		return "", err
	}
	for i := range commands {
		next, err := applyEdCommand(lines, commands[i])
		if err != nil {
			return "", err
		}
		lines = next
		if len(lines) > maxConsensusDiffLines {
			return "", fmt.Errorf("applied consensus too large")
		}
	}
	out := joinConsensusLines(lines)
	if !hexDigestEqual(sha3_256Hex([]byte(out)), to) {
		return "", fmt.Errorf("consensus diff ToDigest mismatch")
	}
	return out, nil
}

type edCommand struct {
	op       byte
	n1, n2   int
	endToEOF bool
	block    []string
}

func parseConsensusDiff(diffDoc string) (from, to string, commands []edCommand, err error) {
	diffDoc = strings.TrimPrefix(diffDoc, "\ufeff")
	diffDoc = strings.ReplaceAll(diffDoc, "\r\n", "\n")
	if !strings.HasSuffix(diffDoc, "\n") {
		diffDoc += "\n"
	}
	rawLines := strings.Split(diffDoc[:len(diffDoc)-1], "\n")
	if len(rawLines) < 3 {
		return "", "", nil, fmt.Errorf("consensus diff too short")
	}
	ver := strings.Fields(rawLines[0])
	if len(ver) != 2 || ver[0] != "network-status-diff-version" || ver[1] != consensusDiffVersion {
		return "", "", nil, fmt.Errorf("unsupported consensus diff version")
	}
	hf := strings.Fields(rawLines[1])
	if len(hf) != 3 || hf[0] != "hash" || !validSHA3Hex(hf[1]) || !validSHA3Hex(hf[2]) {
		return "", "", nil, fmt.Errorf("invalid consensus diff hash line")
	}
	from, to = hf[1], hf[2]
	i := 2
	for i < len(rawLines) {
		if len(commands) >= maxConsensusDiffCommands {
			return "", "", nil, fmt.Errorf("too many consensus diff commands")
		}
		cmd, next, err := parseEdCommand(rawLines, i)
		if err != nil {
			return "", "", nil, err
		}
		commands = append(commands, cmd)
		i = next
	}
	return from, to, commands, nil
}

func parseEdCommand(lines []string, i int) (edCommand, int, error) {
	if i >= len(lines) {
		return edCommand{}, i, fmt.Errorf("unexpected end of consensus diff")
	}
	line := lines[i]
	if line == "" {
		return edCommand{}, i, fmt.Errorf("empty consensus diff command")
	}
	if len(line) > maxEdCommandBytes {
		return edCommand{}, i, fmt.Errorf("ed command too long")
	}
	op := line[len(line)-1]
	if op != 'd' && op != 'c' && op != 'a' {
		return edCommand{}, i, fmt.Errorf("unsupported ed command %q", line)
	}
	rangePart := line[:len(line)-1]
	n1, n2, endToEOF, err := parseEdRange(rangePart, op)
	if err != nil {
		return edCommand{}, i, err
	}
	cmd := edCommand{op: op, n1: n1, n2: n2, endToEOF: endToEOF}
	i++
	if op == 'd' {
		return cmd, i, nil
	}
	block, next, err := parseEdBlock(lines, i)
	if err != nil {
		return edCommand{}, i, err
	}
	if len(block) == 0 {
		return edCommand{}, i, fmt.Errorf("ed command inserts zero lines")
	}
	cmd.block = block
	return cmd, next, nil
}

func parseEdRange(s string, op byte) (n1, n2 int, endToEOF bool, err error) {
	if s == "" {
		return 0, 0, false, fmt.Errorf("missing ed line numbers")
	}
	left, right, hasComma := strings.Cut(s, ",")
	if !edLineNumber(left) {
		return 0, 0, false, fmt.Errorf("invalid ed start line %q", s)
	}
	n1, err = strconv.Atoi(left)
	if err != nil || n1 < 0 {
		return 0, 0, false, fmt.Errorf("invalid ed start line %q", s)
	}
	// C Tor gen_ed_diff 对文件开头插入用 0a；d/c 的行号仍从 1 起。
	if n1 == 0 && op != 'a' {
		return 0, 0, false, fmt.Errorf("invalid ed start line %q", s)
	}
	if !hasComma {
		return n1, n1, false, nil
	}
	if op == 'a' {
		return 0, 0, false, fmt.Errorf("ed append cannot take a range")
	}
	if right == "$" {
		if op != 'd' {
			return 0, 0, false, fmt.Errorf("$ only allowed with delete")
		}
		return n1, 0, true, nil
	}
	if !edLineNumber(right) {
		return 0, 0, false, fmt.Errorf("invalid ed end line %q", s)
	}
	n2, err = strconv.Atoi(right)
	// C Tor apply_ed_diff：带逗号的范围要求 end > start（单行用 n1d / n1c）。
	if err != nil || n2 <= n1 {
		return 0, 0, false, fmt.Errorf("invalid ed end line %q", s)
	}
	return n1, n2, false, nil
}

// edLineNumber 只接受无符号十进制行号（拒绝 +1 / 空白 / 科学计数）。
func edLineNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseEdBlock(lines []string, i int) ([]string, int, error) {
	block := make([]string, 0, 8)
	for i < len(lines) {
		line := lines[i]
		i++
		if line == "." {
			return block, i, nil
		}
		if strings.TrimRight(line, " \t") == "." {
			return nil, i, fmt.Errorf("reject dotted whitespace line in consensus diff")
		}
		if len(line) > maxConsensusLineBytes {
			return nil, i, fmt.Errorf("consensus diff line too long")
		}
		block = append(block, line)
		if len(block) > maxConsensusDiffLines {
			return nil, i, fmt.Errorf("consensus diff block too large")
		}
	}
	return nil, i, fmt.Errorf("unterminated ed block")
}

func applyEdCommand(lines []string, cmd edCommand) ([]string, error) {
	n1, n2 := cmd.n1, cmd.n2
	if cmd.endToEOF {
		if n1 > len(lines)+1 || (n1 > len(lines) && len(lines) > 0) {
			return nil, fmt.Errorf("ed delete past end of file")
		}
		if n1 > len(lines) {
			return lines, nil
		}
		n2 = len(lines)
	}
	switch cmd.op {
	case 'd':
		if err := checkEdSpan(len(lines), n1, n2); err != nil {
			return nil, err
		}
		return spliceLines(lines, n1, n2, nil), nil
	case 'c':
		if err := checkEdSpan(len(lines), n1, n2); err != nil {
			return nil, err
		}
		return spliceLines(lines, n1, n2, cmd.block), nil
	case 'a':
		// n1==0：插到文件开头（C Tor apply_ed_diff 允许 0a）。
		if n1 < 0 || n1 > len(lines) {
			return nil, fmt.Errorf("ed append line out of range")
		}
		out := make([]string, 0, len(lines)+len(cmd.block))
		out = append(out, lines[:n1]...)
		out = append(out, cmd.block...)
		out = append(out, lines[n1:]...)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported ed command")
	}
}

func checkEdSpan(n, n1, n2 int) error {
	if n1 < 1 || n2 < n1 || n2 > n {
		return fmt.Errorf("ed range %d-%d out of %d lines", n1, n2, n)
	}
	return nil
}

func spliceLines(lines []string, n1, n2 int, insert []string) []string {
	out := make([]string, 0, len(lines)-(n2-n1+1)+len(insert))
	out = append(out, lines[:n1-1]...)
	out = append(out, insert...)
	out = append(out, lines[n2:]...)
	return out
}

func firstDirectorySignatureLine(lines []string) int {
	for i, line := range lines {
		// 与 C Tor START_OF_SIGNATURES_SECTION 一致，必须带空格。
		if strings.HasPrefix(line, "directory-signature ") {
			return i + 1
		}
	}
	return 0
}

// checkEdReverseOrder 要求命令从后往前（C Tor apply_ed_diff：end > j 则失败）。
// 通过后，按文件顺序逐条应用到可变行表，与「行号相对原文件」等价。
func checkEdReverseOrder(commands []edCommand, origLen int) error {
	j := origLen
	for i := range commands {
		cmd := commands[i]
		end := cmd.n2
		if cmd.endToEOF {
			end = origLen
		} else if cmd.op == 'a' {
			end = cmd.n1
		}
		if end > j {
			return fmt.Errorf("consensus diff commands not in reverse order")
		}
		if cmd.op == 'a' {
			j = cmd.n1
		} else {
			j = cmd.n1 - 1
		}
	}
	return nil
}

// ConsensusDiffFromDigest 计算 X-Or-Diff-From-Consensus / FromDigest。
// 有签名边界时用 signed part；否则（仅单测无签名文档）哈希整份原文。
func ConsensusDiffFromDigest(oldDoc string) string {
	return consensusDiffFromDigest(oldDoc)
}

func consensusDiffFromDigest(oldDoc string) string {
	if signed, err := extractConsensusSignedBody(oldDoc); err == nil {
		return sha3_256Hex(signed)
	}
	return sha3_256Hex([]byte(oldDoc))
}

func splitConsensusLines(s string) []string {
	s = normalizeConsensusText(s)
	if s == "" {
		return nil
	}
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func checkConsensusLineLengths(lines []string) error {
	for _, line := range lines {
		if len(line) > maxConsensusLineBytes {
			return fmt.Errorf("consensus line too long")
		}
	}
	return nil
}

func joinConsensusLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func normalizeConsensusText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// stripConsensusPreamble 去掉 CollecTor `@type ...` 等位于 network-status-version 之前的前缀。
// limited-ed 行号相对「以 network-status-version 开头」的权威原文；保留前缀会使首个
// directory-signature 行号整体 +1，导致真实 Diff 的 `N,$d` 校验失败。
func stripConsensusPreamble(doc string) string {
	doc = strings.TrimPrefix(doc, "\ufeff")
	idx := strings.Index(doc, "network-status-version")
	if idx <= 0 {
		return doc
	}
	return doc[idx:]
}

func sha3_256Hex(b []byte) string {
	sum := sha3.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validSHA3Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func hexDigestEqual(a, b string) bool {
	return strings.EqualFold(a, b)
}

func isConsensusDiffDocument(raw string) bool {
	return strings.HasPrefix(strings.TrimLeft(raw, "\ufeff"), "network-status-diff-version ")
}
