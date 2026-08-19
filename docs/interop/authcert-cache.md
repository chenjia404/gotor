# 权威证书磁盘缓存（`cached-certs`）

**日期**：2026-08-19  
**状态**：WORKING（2026-08-19 真实验收；官方长期 fixture 仍不入库）

对照：

- dir-spec [authority-key-certificates](https://spec.torproject.org/dir-spec/authority-key-certificates.html)
- C Tor：`cached-certs`（DataDirectory 下拼接的 `dir-key-certificate-version 3` 文档）

## 实现（100% 纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/directory/certcache_disk.go` | 读/写 `cached-certs`，原子替换 |
| `pkg/directory/authcert.go` | 解析 + certification / crosscert |
| `pkg/client` | 启动时 `EnableCertDiskCache(DataDirectory)` |

格式与 C Tor 相同：多份证书原文直接拼接，无 JSON 包装。写入用同目录临时文件 + `rename`，权限 `0600`。

## 加载规则

加载时**重新**做完整校验，不信任磁盘：

1. identity ∈ 硬编码 `KnownAuthorities`
2. `dir-key-certification` / `dir-key-crosscert` PKCS#1 通过
3. `SHA1(PKCS1(identity))` 与 fingerprint / v3ident 一致
4. **`dir-key-expires` 已过则拒绝**（不得使用、不得再写入）

损坏、超大（>2MB）、条目过多：记录警告，以空缓存继续，不让客户端启动失败。

可用性以 `dir-key-expires` 为准（不再用 24h 内存 TTL 把未过期证书打成 stale）。

## 禁止

- 把未通过 certification / crosscert 的证书写入磁盘
- 加载未知权威或过期证书
- 为过测试放松过期检查
- 把实网权威证书提交进仓库并宣称「官方长期 fixture」（实网证书会过期）
- C 库 / CGO

## 离线验收

单测用 `generateTestAuthority` 生成带完整签名的证书（不是从 C Tor 原样导出）：

- 落盘后换进程加载，验签通过，且不再访问 HTTP
- `dir-key-expires` 在过去 → `validateAuthorityCert` 失败，磁盘加载跳过

真实验收：

`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration -run TestRealAuthCertDiskCache`

**结果（2026-08-19）**：PASS。冷启动 key HTTP=9、`cached-certs`=20442 字节；二次启动磁盘加载 9 份证书后 FetchConsensus 的 `/tor/keys/fp` HTTP=**0**。

