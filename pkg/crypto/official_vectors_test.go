package crypto_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOfficialCtorNtorV3FilePresent 确保 Phase 3 官方向量文件为原样导入。
func TestOfficialCtorNtorV3FilePresent(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../.."))
	path := filepath.Join(root, "testdata/ctor-official/test_ntor_v3.c")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing official file: %v", err)
	}
	s := string(b)
	for _, needle := range []string{
		"4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a",
		"expect_client_handshake",
		"9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00f",
	} {
		if !strings.Contains(s, needle) {
			t.Fatalf("official ntor_v3 file missing %q", needle)
		}
	}
}

// TestOfficialCtorCGOVectorsPresent 确保 cgo_vectors.inc 原样存在。
func TestOfficialCtorCGOVectorsPresent(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../.."))
	path := filepath.Join(root, "testdata/ctor-official/cgo_vectors.inc")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing official CGO vectors: %v", err)
	}
	if !strings.Contains(string(b), "CGO test vectors") {
		t.Fatal("unexpected cgo_vectors.inc content")
	}
	if len(b) < 10000 {
		t.Fatalf("cgo_vectors.inc too small: %d", len(b))
	}
}

func TestOfficialCtorCellFormatsPresent(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../.."))
	path := filepath.Join(root, "testdata/ctor-official/test_cell_formats.c")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing official cell formats: %v", err)
	}
	if !strings.Contains(string(b), "Copyright") || len(b) < 1000 {
		t.Fatal("unexpected test_cell_formats.c")
	}
}
