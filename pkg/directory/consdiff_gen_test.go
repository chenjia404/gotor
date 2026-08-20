package directory

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

func TestGenerateConsensusDiffRoundTripSigned(t *testing.T) {
	oldDoc := "network-status-version 3\n" +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"valid-after 2024-01-01 00:00:00\n" +
		"fresh-until 2024-01-01 01:00:00\n" +
		"valid-until 2024-01-01 03:00:00\n" +
		"directory-footer\n" +
		"directory-signature 1 sha256 AAAA BBBB\n-----BEGIN SIGNATURE-----\nxxxx\n-----END SIGNATURE-----\n"
	newDoc := "network-status-version 3\n" +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"valid-after 2024-01-01 01:00:00\n" +
		"fresh-until 2024-01-01 02:00:00\n" +
		"valid-until 2024-01-01 04:00:00\n" +
		"directory-footer\n" +
		"directory-signature 1 sha256 CCCC DDDD\n-----BEGIN SIGNATURE-----\nyy\n-----END SIGNATURE-----\n"
	diff, err := GenerateConsensusDiff(oldDoc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(diff, "network-status-diff-version 1\n") {
		t.Fatalf("missing version: %s", diff)
	}
	sigLine := firstDirectorySignatureLine(splitConsensusLines(oldDoc))
	if !strings.Contains(diff, "\n"+strconv.Itoa(sigLine)+",$d\n") {
		t.Fatalf("含签名的 diff 必须以 %d,$d 开头:\n%s", sigLine, diff)
	}
	got, err := applyConsensusDiff(oldDoc, diff)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got != normalizeConsensusText(newDoc) {
		t.Fatalf("round-trip 不符")
	}
}

func TestGenerateConsensusDiffAlignsRouterIdentity(t *testing.T) {
	idA := base64.RawStdEncoding.EncodeToString(bytesRepeat(0x01, 20))
	idB := base64.RawStdEncoding.EncodeToString(bytesRepeat(0x02, 20))
	idC := base64.RawStdEncoding.EncodeToString(bytesRepeat(0x03, 20))
	oldDoc := joinCons(
		"network-status-version 3",
		"vote-status consensus",
		"r oldA "+idA+" AAAA 2024-01-01 00:00:00 1.2.3.4 9001 0",
		"m AAAA",
		"s Fast Running",
		"r oldB "+idB+" BBBB 2024-01-01 00:00:00 1.2.3.5 9001 0",
		"m BBBB",
		"s Fast Running",
		"directory-footer",
		"directory-signature sha256 AA BB",
		"-----BEGIN SIGNATURE-----",
		"OLD",
		"-----END SIGNATURE-----",
	)
	newDoc := joinCons(
		"network-status-version 3",
		"vote-status consensus",
		"r newA "+idA+" AAAA 2024-01-01 01:00:00 1.2.3.4 9001 0",
		"m AAAA",
		"s Fast Running Stable",
		"r newC "+idC+" CCCC 2024-01-01 01:00:00 1.2.3.6 9001 0",
		"m CCCC",
		"s Fast Running",
		"directory-footer",
		"directory-signature sha256 CC DD",
		"-----BEGIN SIGNATURE-----",
		"NEW",
		"-----END SIGNATURE-----",
	)
	diff, err := GenerateConsensusDiff(oldDoc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	// 身份对齐后不应整份替换正文；B 删除、C 插入、A 就地改。
	if strings.Count(diff, "\nc\n") == 0 && !strings.Contains(diff, "c\n") {
		// 至少应有 c 或 d/a，不能没有任何 ed 命令
		if !strings.Contains(diff, "d\n") && !strings.Contains(diff, "a\n") {
			t.Fatalf("expected ed commands, got:\n%s", diff)
		}
	}
	if strings.Contains(diff, "1,") && strings.Contains(diff, "c\n") && strings.Contains(diff, newDoc) {
		t.Fatalf("不应退化成整份替换:\n%s", diff)
	}
	got, err := applyConsensusDiff(oldDoc, diff)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got != normalizeConsensusText(newDoc) {
		t.Fatalf("apply 结果不符")
	}
	if !strings.Contains(diff, idC) {
		t.Fatal("diff 应包含新增路由身份")
	}
}

func TestGenerateConsensusDiffInsertAtStart(t *testing.T) {
	oldDoc := "keep\nsecond\n"
	newDoc := "inserted\nkeep\nsecond\n"
	diff, err := GenerateConsensusDiff(oldDoc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "0a\n") && !strings.Contains(diff, "1c\n") {
		t.Fatalf("文件首部插入应为 0a 或 1c，得到:\n%s", diff)
	}
}

func TestParseOrDiffFromConsensusHeader(t *testing.T) {
	h1 := strings.Repeat("a", 64)
	h2 := strings.Repeat("b", 64)
	got := ParseOrDiffFromConsensusHeader(h1 + ", " + strings.ToUpper(h2) + " " + h1)
	if len(got) != 2 || got[0] != h1 || got[1] != h2 {
		t.Fatalf("got %#v", got)
	}
	if ParseOrDiffFromConsensusHeader("not-hex") != nil {
		t.Fatal("非法摘要应忽略")
	}
}

func TestConsensusDiffFromDigestExported(t *testing.T) {
	doc := "network-status-version 3\nbody\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nX\n-----END SIGNATURE-----\n"
	if ConsensusDiffFromDigest(doc) != consensusDiffFromDigest(doc) {
		t.Fatal("exported digest 必须与内部一致")
	}
}

func joinCons(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}
