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
| `GET /tor/status-vote/current/consensus-microdesc/diff/<HASH>/<FPRLIST>` | 匹配则 200 + limited-ed；FPRLIST 过半签名才返回，否则 404 |
| `GET /tor/status-vote/current/consensus-microdesc/<FPRLIST>` | 超过半数被请求权威已签名则回过滤后的共识；`all` / 无列表回全部签名 |
| 同上 `consensus`（非 flavor）路径 | 与现有行为一致：仍服务 `cached-microdesc-consensus` |
| BEGIN_DIR | 同一 handler |
| `CacheDirectory/cached-microdesc-consensus.prev` | 换共识时保留上一份，供生成 diff |

生成算法在 `pkg/directory/consdiff_gen.go`：先 `n,$d` 去掉旧签名段，再按 `r` 行身份对齐分块 LCS，命令从后往前。只产出 `d`/`c`/`a`（含 C Tor 的 `0a`）。成功后用现有 `applyConsensusDiff` 自检。

## 本切片已做（2026-08-20 压缩 / 304）

对照 dir-spec [standards-compliance](https://spec.torproject.org/dir-spec/standards-compliance.html)。

- `Accept-Encoding: gzip` / `deflate` → 对应 `Content-Encoding`
- 路径 `.z` **且无** `Accept-Encoding`：zlib deflate，**不**带 `Content-Encoding`（旧客户端）
- 路径 `.z` **且有** `Accept-Encoding`：按无 `.z` 协商（须在 advertised 集合内编码一次）
- 共识 `Last-Modified` 用 `valid-after`（UTC）；`If-Modified-Since` ≥ 该时刻则 **304** 无正文。坏 IMS 忽略。
- 其它落盘文档用文件 mtime。
- **仍禁止** 在 `proto` 写 `DirCache=2`

## 本切片已做（2026-08-20 FPRLIST）

对照 dir-spec [general-use-http-urls](https://spec.torproject.org/dir-spec/general-use-http-urls.html) 的 FPRLIST。

- `+` 分隔的身份十六进制前缀（2–40 偶数位）；`all` / 空列表 = 不筛选。
- 按 `directory-signature` 的 identity 前缀保留签名块；须超过半数被请求权威已签名，否则 404。
- 过滤不改 signed body，diff 缓存键含 FPRLIST。
- **仍禁止** 在 `proto` 写 `DirCache=2`

## 本切片已做（2026-08-20 x-zstd / x-tor-lzma）

对照 dir-spec [standards-compliance](https://spec.torproject.org/dir-spec/standards-compliance.html)。

- 协商顺序：`x-tor-lzma` → `x-zstd` → `gzip` → `deflate`（与 C Tor 预压缩偏好一致）。
- `x-zstd`：标准 zstd，单线程实时编码。
- `x-tor-lzma`：LZMA Alone（非 xz 容器），字典 ≤ 8MiB（preset 6）；只缓存整份共识与 limited-ed（最多 2 份）。
- FPRLIST 过滤体、证书、microdesc、HS 描述符若请求 lzma，退回 zstd/gzip/deflate，不实时 LZMA。
- **仍禁止** 在 `proto` 写 `DirCache=2`

## 明确未做（因此禁止 `DirCache=2`）

- 多小时 / 多份历史共识的 diff 库（客户端落后两期以上只能拿到整份）
- ns flavor 与 microdesc 分库存放
- 真网官方客户端把本中继当 DirCache 的证据；权威 V2Dir 仍取决于 Running / 可达性，不由本切片单独证明

## 禁止

- 在 `proto` 写 `DirCache=2`
- 只开 DirPort 回 200 空体
- 用明文 DirPort 拉 HS 描述符并宣称安全
