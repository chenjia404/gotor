package directory

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
)

// CompressDirBody 按 DirPort 协商结果压缩目录文档。
// gzip / zlib deflate / 标准 zstd / LZMA Alone（preset ≤ 6，字典 8MiB）。
// 失败时返回原文且 used=""，调用方按未压缩发出。
func CompressDirBody(enc string, body []byte) (payload []byte, used string) {
	switch enc {
	case "gzip":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return body, ""
		}
		if err := zw.Close(); err != nil {
			return body, ""
		}
		return buf.Bytes(), "gzip"
	case "deflate":
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return body, ""
		}
		if err := zw.Close(); err != nil {
			return body, ""
		}
		return buf.Bytes(), "deflate"
	case "x-zstd":
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
		if err != nil {
			return body, ""
		}
		if _, err := zw.Write(body); err != nil {
			_ = zw.Close()
			return body, ""
		}
		if err := zw.Close(); err != nil {
			return body, ""
		}
		return buf.Bytes(), "x-zstd"
	case "x-tor-lzma":
		// C Tor 用 lzma_alone_encoder（legacy .lzma），不是 xz 容器。
		// dir-spec：preset 不得高于 6（约 8MiB 字典）。
		var buf bytes.Buffer
		zw, err := lzma.WriterConfig{DictCap: 8 << 20}.NewWriter(&buf)
		if err != nil {
			return body, ""
		}
		if _, err := zw.Write(body); err != nil {
			_ = zw.Close()
			return body, ""
		}
		if err := zw.Close(); err != nil {
			return body, ""
		}
		return buf.Bytes(), "x-tor-lzma"
	default:
		return body, ""
	}
}
