# Arti 官方原样源文件（禁止改写 hex）

从 Tor Project `arti` 仓库原样拷贝，未重新生成向量。

| 文件 | 上游路径 | 用途 |
|------|----------|------|
| `ntor_v3.rs` | `crates/tor-proto/src/crypto/handshake/ntor_v3.rs` | proposal 332 握手与期望 hex |
| `hs_ntor.rs` | `crates/tor-proto/src/crypto/handshake/hs_ntor.rs` | hs-ntor 实现与测试向量 |

对照：`pkg/crypto/ntorv3_test.go`、`hs_ntor_test.go` 中的 hex 应与上述文件一致。
