# C Tor 官方原样向量（禁止改写）

本目录文件从 Tor Project `tor` 仓库 **原样** 拷贝，未重新生成、未改 hex。

| 文件 | 上游路径 | 用途 |
|------|----------|------|
| `cgo_vectors.inc` | `src/test/cgo_vectors.inc` | Relay=6 CGO / Polyval |
| `test_ntor_v3.c` | `src/test/test_ntor_v3.c` | ntor-v3 握手期望值 |
| `test_cell_formats.c` | `src/test/test_cell_formats.c` | 固定/可变 cell 编解码 |
| `cell_connected_vectors.json` | 自 `test_cell_formats.c` 抽取 | CONNECTED / CREATE2 ntor 头 Go fixture |

来源 commit：见 git 历史；导入时对齐 tor `main` / `tor-0.4.8.x`。

`pkg/crypto/cgo_test.go` 与 `ntorv3_test.go` 中的 hex 应与这些文件一致。
`testdata/ctor-vectors/` 下 JSON 仍为规范重算向量，**不得**单独宣称「官方原样」。
