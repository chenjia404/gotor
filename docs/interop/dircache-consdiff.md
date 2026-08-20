# 中继对外 consdiff（limited-ed）

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；**未**宣告 `DirCache=2`）

对照：

- dir-spec [directory-cache-operation](https://spec.torproject.org/dir-spec/directory-cache-operation.html)
- dir-spec [limited-ed-diff-format](https://spec.torproject.org/dir-spec/limited-ed-diff-format.html)
- dir-spec [general-use-http-urls](https://spec.torproject.org/dir-spec/general-use-http-urls.html)

客户端 **拉** consdiff 仍见 [`consensus-diff.md`](consensus-diff.md)。本文件只讲中继 **对外服务**。

## 本切片已做

| 路径 | 行为 |
|------|------|
| `GET /tor/status-vote/current/consensus-microdesc` 带 `X-Or-Diff-From-Consensus` | 若摘要匹配上一份落盘共识，回 limited-ed；否则回整份当前共识 |
| `GET /tor/status-vote/current/consensus-microdesc/diff/<HASH>/<FPRLIST>` | 匹配则 200 + limited-ed；否则 404 |
| 同上 `consensus`（非 flavor）路径 | 与现有行为一致：仍服务 `cached-microdesc-consensus` |
| BEGIN_DIR | 同一 handler |
| `CacheDirectory/cached-microdesc-consensus.prev` | 换共识时保留上一份，供生成 diff |

生成算法在 `pkg/directory/consdiff_gen.go`：先 `n,$d` 去掉旧签名段，再按 `r` 行身份对齐分块 LCS，命令从后往前。只产出 `d`/`c`/`a`（含 C Tor 的 `0a`）。成功后用现有 `applyConsensusDiff` 自检。

## 本切片已做（2026-08-20 压缩 / 304）

- `Accept-Encoding: gzip` → `Content-Encoding: gzip`
- `Accept-Encoding: deflate` 或路径 `.z` → zlib（`Content-Encoding: deflate`）
- `If-Modified-Since` 与落盘 `Last-Modified` 对齐则 **304**（无正文）
- **仍禁止** 在 `proto` 写 `DirCache=2`

## 明确未做（因此禁止 `DirCache=2`）

- 多小时 / 多份历史共识的 diff 库（客户端落后两期以上只能拿到整份）
- zstd / lzma
- 按 FPRLIST 过滤权威签名子集
- ns flavor 与 microdesc 分库存放
- 真网官方客户端把本中继当 DirCache 的证据；权威 V2Dir 仍取决于 Running / 可达性，不由本切片单独证明

## 禁止

- 在 `proto` 写 `DirCache=2`
- 只开 DirPort 回 200 空体
- 用明文 DirPort 拉 HS 描述符并宣称安全
