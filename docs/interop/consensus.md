# 共识签名（dir-spec / C Tor）

**状态**：生产 `FetchConsensus` 强制验签。真实网络 `TestRealConsensusSignatures` 已通过（9/9 权威，10143 relays）。

HTTP 目录端口仍可能 `InsecureSkipVerify`。没有密码学验签时，MITM 可喂假共识。验签后，攻击者必须同时掌握 **≥5 个** 硬编码权威的 identity 私钥。

`r` / `valid-*` / `params` **只解析签名范围**（`network-status-version` … 第一个 `directory-signature `）。签名行从该关键字起另解析。未签名前缀/后缀里的 relay 或 `valid-until` 不得进入结果。

## 对照

- Spec：https://spec.torproject.org/dir-spec/consensus-formats.html
- Spec：https://spec.torproject.org/dir-spec/authority-key-certificates.html
- Consensus diff（DirCache=2）：见 `docs/interop/consensus-diff.md`
- C Tor：`router_get_networkstatus_v3_signed_boundaries`
- C Tor：`authority_cert_parse_from_string` / dir-key-certification

## 签名范围

共识 signed body 从 `network-status-version` 起到第一个 `\ndirectory-signature` **再含 keyword 后的空格**，不含 `sha256 identity signing-key`。所有权威签同一前缀。

microdesc 共识的 `directory-signature` 算法为 `sha256`。

## 证书

- 磁盘缓存见 `docs/interop/authcert-cache.md`（`DataDirectory/cached-certs`）。
- 拉取 `/tor/keys/fp/<IDENTITY>`，不要只用 `/tor/keys/authority` 的第一把 RSA（那是 identity，不是 signing）。
- `dir-signing-key` 才是验共识的公钥。
- `SHA1(PKCS1(identity))` 必须等于硬编码 `KnownAuthorities.V3Ident`。
- `SHA1(PKCS1(signing))` 必须等于共识 `directory-signature` 的 signing-key-digest。
- `dir-key-certification`：从 `dir-key-certificate-version` 到 `dir-key-certification\n`，SHA-1，identity 私钥，PKCS#1（不含 algorithmIdentifier）。
- `dir-key-crosscert`：实网 PEM 类型为 `ID SIGNATURE`，payload 为 `SHA1(PKCS1(identity))`，signing 私钥签。

## PKCS#1

「signature does not include the algorithmIdentifier」→ Go 中为 `rsa.VerifyPKCS1v15(pub, 0, hash, sig)`。
