package directory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestApplyConsensusDiffDeleteChangeAdd(t *testing.T) {
	oldDoc := "alpha\nbeta\ngamma\ndelta\n"
	want := "alpha\ninserted\nBETA\ngamma\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + sha3_256Hex([]byte(want)) + "\n" +
		"4d\n" +
		"2c\n" +
		"BETA\n" +
		".\n" +
		"1a\n" +
		"inserted\n" +
		".\n"

	got, err := applyConsensusDiff(oldDoc, diff)
	if err != nil {
		t.Fatalf("applyConsensusDiff: %v", err)
	}
	if got != normalizeConsensusText(want) {
		t.Fatalf("结果不符:\n%s", got)
	}
}

func TestApplyConsensusDiffRangeDeleteAndChange(t *testing.T) {
	oldDoc := "L1\nL2\nL3\nL4\nL5\n"
	want := "L1\nX\nY\nL5\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + sha3_256Hex([]byte(want)) + "\n" +
		"4d\n" +
		"2,3c\n" +
		"X\n" +
		"Y\n" +
		".\n"
	got, err := applyConsensusDiff(oldDoc, diff)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got != normalizeConsensusText(want) {
		t.Fatalf("got %q", got)
	}
}

func TestApplyConsensusDiffDollarDelete(t *testing.T) {
	oldDoc := "keep\nremove-me\n"
	want := "keep\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + sha3_256Hex([]byte(want)) + "\n" +
		"2,$d\n"
	got, err := applyConsensusDiff(oldDoc, diff)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got != normalizeConsensusText(want) {
		t.Fatalf("got %q", got)
	}
}

func TestApplyConsensusDiffHashCaseInsensitive(t *testing.T) {
	oldDoc := "keep\nremove-me\n"
	want := "keep\n"
	from := strings.ToUpper(consensusDiffFromDigest(oldDoc))
	to := strings.ToUpper(sha3_256Hex([]byte(want)))
	diff := "network-status-diff-version 1\n" +
		"hash " + from + " " + to + "\n" +
		"2,$d\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err != nil {
		t.Fatalf("大小写不同的 hex 应被接受: %v", err)
	}
}

func TestMakeConsensusDiffRoundTrip(t *testing.T) {
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
	diff, err := makeConsensusDiff(oldDoc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	sigLine := firstDirectorySignatureLine(splitConsensusLines(oldDoc))
	wantCmd := "\n" + strconv.Itoa(sigLine) + ",$d\n"
	if !strings.Contains(diff, wantCmd) {
		t.Fatalf("含签名的 diff 必须以 %d,$d 开头，得到:\n%s", sigLine, diff)
	}
	got, err := applyConsensusDiff(oldDoc, diff)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if got != normalizeConsensusText(newDoc) {
		t.Fatalf("round-trip 结果不符:\n%s", got)
	}
}

func TestApplyConsensusDiffFromDigestUsesSignedBody(t *testing.T) {
	oldDoc := "network-status-version 3\nbody\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nOLD\n-----END SIGNATURE-----\n"
	newDoc := "network-status-version 3\nbody2\ndirectory-signature sha256 CC DD\n-----BEGIN SIGNATURE-----\nNEW\n-----END SIGNATURE-----\n"
	diff, err := makeConsensusDiff(oldDoc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	from := strings.Fields(strings.Split(diff, "\n")[1])[1]
	signed, err := extractConsensusSignedBody(oldDoc)
	if err != nil {
		t.Fatal(err)
	}
	if !hexDigestEqual(from, sha3_256Hex(signed)) {
		t.Fatalf("FromDigest 必须是 signed part，got %s want %s", from, sha3_256Hex(signed))
	}
	if hexDigestEqual(from, sha3_256Hex([]byte(oldDoc))) {
		t.Fatal("FromDigest 不应是整份旧文档（含签名块）")
	}
}

func TestApplyConsensusDiffRejectsBadHash(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + strings.Repeat("0", 64) + " " + strings.Repeat("1", 64) + "\n" +
		"2d\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望 FromDigest 不匹配失败")
	}
}

func TestApplyConsensusDiffRejectsToDigestMismatch(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("f", 64) + "\n" +
		"2d\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望 ToDigest 不匹配失败")
	}
}

func TestApplyConsensusDiffRejectsUnknownCommand(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("1", 64) + "\n" +
		"1s/foo/bar/\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝未知 ed 命令")
	}
}

func TestApplyConsensusDiffRejectsAppendRange(t *testing.T) {
	oldDoc := "a\nb\nc\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("1", 64) + "\n" +
		"1,2a\n" +
		"x\n" +
		".\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝带范围的 a")
	}
}

func TestApplyConsensusDiffRejectsForwardOrder(t *testing.T) {
	oldDoc := "a\nb\nc\n"
	want := "a\nX\n"
	// 先改第 1 行再删后面，不是从后往前。
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + sha3_256Hex([]byte(want)) + "\n" +
		"1c\n" +
		"X\n" +
		".\n" +
		"2,3d\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝非从后往前的命令")
	}
}

func TestApplyConsensusDiffRejectsBareA(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("1", 64) + "\n" +
		"a\n" +
		"x\n" +
		".\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝无行号的 a")
	}
}

func TestApplyConsensusDiffRejectsSignedPlusMinusLine(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("1", 64) + "\n" +
		"+2d\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝 +2d")
	}
}

func TestApplyConsensusDiffRejectsDotOnlyInsert(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("1", 64) + "\n" +
		"1a\n" +
		".\n" +
		".\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝插入单独的点行")
	}
}

func TestApplyConsensusDiffRejectsDotWithWhitespace(t *testing.T) {
	oldDoc := "a\nb\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + strings.Repeat("1", 64) + "\n" +
		"1a\n" +
		". \n" +
		".\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝点后带空白的插入行")
	}
}

func TestApplyConsensusDiffRequiresDollarDeleteWhenSigned(t *testing.T) {
	oldDoc := "network-status-version 3\nbody\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nxx\n-----END SIGNATURE-----\n"
	want := "network-status-version 3\nbody2\ndirectory-signature sha256 CC DD\n-----BEGIN SIGNATURE-----\nyy\n-----END SIGNATURE-----\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + sha3_256Hex([]byte(want)) + "\n" +
		"1c\n" +
		"body2\n" +
		".\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝缺少 n,$d 的已签名文档 diff")
	}
}

func TestApplyConsensusDiffRequiresFirstSignatureLine(t *testing.T) {
	oldDoc := "network-status-version 3\nbody\ndirectory-signature sha256 AA BB\n-----BEGIN SIGNATURE-----\nxx\n-----END SIGNATURE-----\n"
	// n 不是首个 directory-signature 行（最后一行的 $d）。
	last := len(splitConsensusLines(oldDoc))
	want := "network-status-version 3\nbody2\n"
	diff := "network-status-diff-version 1\n" +
		"hash " + consensusDiffFromDigest(oldDoc) + " " + sha3_256Hex([]byte(want)) + "\n" +
		strconv.Itoa(last) + ",$d\n"
	if _, err := applyConsensusDiff(oldDoc, diff); err == nil {
		t.Fatal("期望拒绝未从首个签名行删除的 n,$d")
	}
}

func TestIsConsensusDiffDocument(t *testing.T) {
	if !isConsensusDiffDocument("network-status-diff-version 1\nhash aa bb\n") {
		t.Fatal("应识别 diff")
	}
	if isConsensusDiffDocument("network-status-version 3\n") {
		t.Fatal("不应把完整共识当成 diff")
	}
}

func TestFetchConsensusAppliesLimitedEdDiff(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)
	consA := buildSignedConsensusExtra(t, auths, "params cc_alg=2\n")
	consB := buildSignedConsensusExtra(t, auths, "params cc_alg=3\n")
	diff, err := makeConsensusDiff(consA, consB)
	if err != nil {
		t.Fatal(err)
	}

	var sawHeader atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tor/keys/fp/") {
			id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
			for _, a := range auths {
				if a.dir.V3Ident == id {
					_, _ = w.Write([]byte(a.certPEM))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(r.URL.Path, "consensus") {
			http.NotFound(w, r)
			return
		}
		h := r.Header.Get("X-Or-Diff-From-Consensus")
		if h == "" {
			_, _ = w.Write([]byte(consA))
			return
		}
		sawHeader.Store(h)
		want := consensusDiffFromDigest(consA)
		if !hexDigestEqual(h, want) {
			t.Errorf("diff header = %s, want %s", h, want)
		}
		_, _ = w.Write([]byte(diff))
	}))
	defer server.Close()

	client := NewClient(logger.NewDefault())
	client.httpClient = server.Client()
	client.authorities = []string{server.URL + "/tor/status-vote/current/consensus-microdesc"}

	relays, err := client.FetchConsensus(context.Background())
	if err != nil {
		t.Fatalf("第一次 FetchConsensus: %v", err)
	}
	if len(relays) != 1 || relays[0].Nickname != "TestRelay" {
		t.Fatalf("第一次 relays = %+v", relays)
	}
	if got := client.LastConsensusParams()["cc_alg"]; got != 2 {
		t.Fatalf("第一次 params cc_alg=%d, want 2", got)
	}

	relays, err = client.FetchConsensus(context.Background())
	if err != nil {
		t.Fatalf("第二次 FetchConsensus（diff）: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("第二次 relays = %d", len(relays))
	}
	if got := client.LastConsensusParams()["cc_alg"]; got != 3 {
		t.Fatalf("第二次 params cc_alg=%d, want 3（diff 未生效）", got)
	}
	h, _ := sawHeader.Load().(string)
	if h == "" {
		t.Fatal("第二次请求应带 X-Or-Diff-From-Consensus")
	}
	if client.cachedSignedSHA3() != consensusDiffFromDigest(consB) {
		t.Fatal("验签成功后应缓存新共识的 signed SHA3")
	}
}

func TestFetchConsensusDiffFailureFallsBackToFull(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)
	consA := buildSignedConsensusExtra(t, auths, "params cc_alg=2\n")
	consB := buildSignedConsensusExtra(t, auths, "params cc_alg=3\n")

	var withHeader, withoutHeader atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tor/keys/fp/") {
			id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
			for _, a := range auths {
				if a.dir.V3Ident == id {
					_, _ = w.Write([]byte(a.certPEM))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		h := r.Header.Get("X-Or-Diff-From-Consensus")
		if h == "" {
			withoutHeader.Add(1)
			if withoutHeader.Load() == 1 {
				_, _ = w.Write([]byte(consA))
				return
			}
			_, _ = w.Write([]byte(consB))
			return
		}
		withHeader.Add(1)
		_, _ = w.Write([]byte("network-status-diff-version 1\nhash " +
			strings.Repeat("0", 64) + " " + strings.Repeat("1", 64) + "\n1s/nope/\n"))
	}))
	defer server.Close()

	client := NewClient(logger.NewDefault())
	client.httpClient = server.Client()
	client.authorities = []string{server.URL + "/tor/status-vote/current/consensus-microdesc"}

	if _, err := client.FetchConsensus(context.Background()); err != nil {
		t.Fatalf("第一次: %v", err)
	}
	if _, err := client.FetchConsensus(context.Background()); err != nil {
		t.Fatalf("回退整份应成功: %v", err)
	}
	if withHeader.Load() < 1 {
		t.Fatal("第二次应先带 diff header")
	}
	if withoutHeader.Load() < 2 {
		t.Fatalf("畸形 diff 后应去掉 header 重拉整份, got withoutHeader=%d", withoutHeader.Load())
	}
	if got := client.LastConsensusParams()["cc_alg"]; got != 3 {
		t.Fatalf("回退后 params cc_alg=%d, want 3", got)
	}
	if client.cachedSignedSHA3() != consensusDiffFromDigest(consB) {
		t.Fatal("回退验签成功后应缓存 B，不得留下失败的 apply 结果")
	}
}

func TestFetchConsensusDiffVerifyFailureDoesNotCache(t *testing.T) {
	auths := make([]*testAuthority, 5)
	for i := range auths {
		auths[i] = generateTestAuthority(t, fmt.Sprintf("auth%d", i))
	}
	withTestAuthorities(t, auths)
	consA := buildSignedConsensusExtra(t, auths, "params cc_alg=2\n")
	consB := buildSignedConsensusExtra(t, auths, "params cc_alg=3\n")
	tampered := strings.Replace(consB, "cc_alg=3", "cc_alg=9", 1)
	diff, err := makeConsensusDiff(consA, tampered)
	if err != nil {
		t.Fatal(err)
	}

	var fullB atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tor/keys/fp/") {
			id := strings.TrimPrefix(r.URL.Path, "/tor/keys/fp/")
			for _, a := range auths {
				if a.dir.V3Ident == id {
					_, _ = w.Write([]byte(a.certPEM))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		h := r.Header.Get("X-Or-Diff-From-Consensus")
		if h == "" {
			if fullB.Add(1) == 1 {
				_, _ = w.Write([]byte(consA))
				return
			}
			_, _ = w.Write([]byte(consB))
			return
		}
		_, _ = w.Write([]byte(diff))
	}))
	defer server.Close()

	client := NewClient(logger.NewDefault())
	client.httpClient = server.Client()
	client.authorities = []string{server.URL + "/tor/status-vote/current/consensus-microdesc"}

	if _, err := client.FetchConsensus(context.Background()); err != nil {
		t.Fatalf("第一次: %v", err)
	}
	hashA := client.cachedSignedSHA3()
	if _, err := client.FetchConsensus(context.Background()); err != nil {
		t.Fatalf("篡改 diff 验签失败后应回退整份 B: %v", err)
	}
	if got := client.LastConsensusParams()["cc_alg"]; got != 3 {
		t.Fatalf("回退后 cc_alg=%d, want 3", got)
	}
	if client.cachedSignedSHA3() == consensusDiffFromDigest(tampered) {
		t.Fatal("不得把未通过验签的 apply 结果写入缓存")
	}
	if client.cachedSignedSHA3() == hashA {
		t.Fatal("回退成功后缓存应更新为 B")
	}
	if client.cachedSignedSHA3() != consensusDiffFromDigest(consB) {
		t.Fatal("缓存应为验签通过的 B")
	}
}

func makeConsensusDiff(oldDoc, newDoc string) (string, error) {
	oldNorm := normalizeConsensusText(oldDoc)
	newNorm := normalizeConsensusText(newDoc)
	from := consensusDiffFromDigest(oldDoc)
	to := sha3_256Hex([]byte(newNorm))
	oldLines := splitConsensusLines(oldNorm)
	newLines := splitConsensusLines(newNorm)
	if len(oldLines) < 2 {
		return "", fmt.Errorf("makeConsensusDiff: 旧文档行数不足")
	}
	delStart := firstDirectorySignatureLine(oldLines)
	if delStart == 0 {
		delStart = len(oldLines)
	}
	if delStart < 2 {
		return "", fmt.Errorf("makeConsensusDiff: 无法在保留正文的前提下构造 n,$d")
	}
	var b strings.Builder
	b.WriteString("network-status-diff-version 1\n")
	b.WriteString("hash ")
	b.WriteString(from)
	b.WriteByte(' ')
	b.WriteString(to)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(delStart))
	b.WriteString(",$d\n")
	b.WriteString("1,")
	b.WriteString(strconv.Itoa(delStart - 1))
	b.WriteString("c\n")
	for _, line := range newLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(".\n")
	return b.String(), nil
}
