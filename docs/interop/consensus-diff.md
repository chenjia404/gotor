# Consensus diff（DirCache=2）

**日期**：2026-08-19  
**状态**：PARTIAL（纯 Go 实现 + httptest；未跑真实权威/缓存）

对照：

- dir-spec [directory-cache-operation](https://spec.torproject.org/dir-spec/directory-cache-operation.html)（Consensus diffs）
- dir-spec [limited-ed-diff-format](https://spec.torproject.org/dir-spec/limited-ed-diff-format.html)
- 子协议 `DirCache=2`（`DIRCACHE_CONSDIFF`）

## 实现（100% 纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/directory/consdiff.go` | 解析 / 应用 limited ed；SHA3-256 FromDigest / ToDigest |
| `pkg/directory/directory.go` | 有缓存时发 `X-Or-Diff-From-Consensus`；失败回退整份 |

SHA3 使用 `golang.org/x/crypto/sha3`，无 CGO、无 `import "C"`。

## 格式

1. 第一行：`network-status-diff-version 1`
2. 第二行：`hash FromDigest ToDigest`（各 64 个十六进制字符）
3. 其后只接受：`n1d`、`n1,n2d`、`n1,$d`、`n1c`、`n1,n2c`、`n1a`
4. 行号 1-indexed；按文件顺序应用（生成方已从后往前编号）
5. 旧文档含 `directory-signature` 时，**第一条必须是「首个签名行,$d」**
6. `c`/`a` 块以单独一行 `.` 结束；拒绝点后带空白的行（无法插入只有一个点的行）

## 哈希语义

- **FromDigest**：旧共识 **signed part** 的 SHA3-256（到第一个 `directory-signature` 后的空格，与 `extractConsensusSignedBody` 一致）
- **ToDigest**：应用后**整份**新共识（含签名）的 SHA3-256
- HTTP 头 `X-Or-Diff-From-Consensus` 发送小写 hex；比较用大小写不敏感

## 回退

同一权威上，下列情况去掉 header 重拉整份 `consensus-microdesc`：

- 带 header 的请求非 200
- 响应是 diff 但 apply / FromDigest / ToDigest 失败
- apply 成功但 metadata / 验签失败

未通过验签的 apply 结果**不得**写入缓存。整份请求若仍返回 diff，直接失败并换权威。

## 禁止

- 接受无行号的 `a` 或其他 ed 命令（含 `s` / `+n`）
- 把未验签文档当成功缓存
- 为过测试放宽 ToDigest / 签名校验
- C 库 / CGO

## 真实验收

待 `TOR_INTEGRATION_TEST=1` 在真实 DirCache=2 镜像上验证：第二次拉取为 diff、验签通过、失败路径回退整份。
