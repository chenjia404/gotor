package directory

import (
	"strings"
	"testing"
)

func TestParseFPRLIST(t *testing.T) {
	fps, filter, ok := ParseFPRLIST("")
	if !ok || filter || len(fps) != 0 {
		t.Fatalf("empty: fps=%v filter=%v ok=%v", fps, filter, ok)
	}
	_, filter, ok = ParseFPRLIST("all")
	if !ok || filter {
		t.Fatal("all 不筛选")
	}
	fps, filter, ok = ParseFPRLIST("AAAAAA+bbbbbb")
	if !ok || !filter || len(fps) != 2 || fps[0] != "aaaaaa" || fps[1] != "bbbbbb" {
		t.Fatalf("got %v filter=%v ok=%v", fps, filter, ok)
	}
	fps, filter, ok = ParseFPRLIST("AAAAAA+AAAAAA")
	if !ok || !filter || len(fps) != 1 {
		t.Fatalf("去重失败 %v", fps)
	}
	if _, _, ok = ParseFPRLIST("xyz"); ok {
		t.Fatal("非 hex 必须拒绝")
	}
	if _, _, ok = ParseFPRLIST("AAA"); ok {
		t.Fatal("奇数长度必须拒绝")
	}
	if _, _, ok = ParseFPRLIST("../aa"); ok {
		t.Fatal(".. 必须拒绝")
	}
}

func TestFilterConsensusByFPRLISTMajority(t *testing.T) {
	doc := "" +
		"network-status-version 3\n" +
		"directory-footer\n" +
		"directory-signature sha256 AAAAAAAAAA1111111111AAAAAAAAAA1111111111 SA\n-----BEGIN SIGNATURE-----\nA\n-----END SIGNATURE-----\n" +
		"directory-signature sha256 BBBBBBBBBB2222222222BBBBBBBBBB2222222222 SB\n-----BEGIN SIGNATURE-----\nB\n-----END SIGNATURE-----\n" +
		"directory-signature sha256 CCCCCCCCCC3333333333CCCCCCCCCC3333333333 SC\n-----BEGIN SIGNATURE-----\nC\n-----END SIGNATURE-----\n"
	a := "aaaaaaaaaa1111111111aaaaaaaaaa1111111111"
	b := "bbbbbbbbbb2222222222bbbbbbbbbb2222222222"
	z := "ffffffffffffffffffffffffffffffffffffffff"

	out, matched, ok := FilterConsensusByFPRLIST(doc, []string{a, b})
	if !ok || matched != 2 {
		t.Fatalf("matched=%d ok=%v", matched, ok)
	}
	if !strings.Contains(out, "AAAAAAAAAA") || !strings.Contains(out, "BBBBBBBBBB") || strings.Contains(out, "CCCCCCCCCC") {
		t.Fatalf("应只留 A+B, got %q", out)
	}
	if !FPRLISTHasMajority(2, matched) {
		t.Fatal("2/2 应过半")
	}

	_, matched, ok = FilterConsensusByFPRLIST(doc, []string{a[:6], z})
	if !ok || matched != 1 {
		t.Fatalf("短前缀 matched=%d ok=%v", matched, ok)
	}
	if FPRLISTHasMajority(2, matched) {
		t.Fatal("1/2 不得过半")
	}

	plain, matched, ok := FilterConsensusByFPRLIST(doc, nil)
	if !ok || matched != 0 || plain != doc {
		t.Fatal("空 fps 必须原样返回")
	}
}
