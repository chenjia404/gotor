# CERTS / Ed25519 证书互操作

**日期**：2026-08-18

## 问题

真实 Guard 在 VERSIONS 协商到 v5 后，CERTS type 4 验签失败：

```
type 4 (Ed25519 signing key) signature verification failed against identity key:
Ed25519 signature verification failed
```

type 7（RSA→Ed25519 cross-cert）已能解析出 identity 公钥。失败发生在用该公钥验证 type 4。

## Tor Spec

https://spec.torproject.org/cert-spec.html

1. Ed25519 证书签名覆盖 `SIGNATURE` 之前的全部字段。
2. **没有** prefix 字符串（spec 原文：*this signature is not personalized with a prefix string*）。
3. 扩展编码：

   | 字段 | 长度 | 含义 |
   |------|------|------|
   | ExtLen | 2 | **仅** ExtData 长度 |
   | ExtType | 1 | 扩展类型 |
   | ExtFlags | 1 | 标志 |
   | ExtData | ExtLen | 扩展体 |

4. `signed-with-ed25519-key`（ExtType `04`）：`ExtLen = 32`，`ExtData` 为签名公钥。
5. CERTS type 7 不是 Ed25519 证书，而是 RSA→Ed25519 cross-cert：

   `ED25519_KEY(32) || EXPIRATION(4) || SIGLEN(1) || SIGNATURE`

6. type 4 的 `CERTIFIED_KEY` 是中期 **signing key**，不是长期 identity。
   长期 identity 在 type 7 的 `ED25519_KEY`，或 type 4 的 signed-with-ed25519-key 扩展。

## C Tor

- 握手 CERTS：`src/core/or/connection_or.c`、`or_handshake_certs_*`
- Ed25519 证书：`src/feature/nodelist/torcert.c`
- 历史上 trunnel 曾把 `ext_length` 解释为包含 type+flags（`ext_length-2`）。
- 与现行 Arti / spec 互操作的线上证书使用 `ExtLen = len(ExtData)`。
- RSA→Ed25519 cross-cert：`ED25519_KEY || EXPIRATION || SIG`，RSA-PKCS1 签 `SHA256("Tor TLS RSA/Ed25519 cross-certificate" || fields)`。

## Arti

`crates/tor-cert/src/lib.rs`（`Readable for CertExt`）：

```text
let len = b.take_u16()?;
let ext_type = b.take_u8()?;
let flags = b.take_u8()?;
let body = b.take(len as usize)?;
```

`crates/tor-cert/src/encode.rs`（`SignedWithEd25519Ext`）：

```text
w.write_u16(32);           // body length only
w.write_u8(SIGNED_WITH_ED25519_KEY);
w.write_u8(0);
w.write_all(pk);           // 32 bytes
```

注释写明：*the length field doesn't include the type or the flags*。

验签使用原始编码字节 `cert[0..sig_offset]`，不加 prefix。

## gotor 曾经的行为

1. 把 `ExtLen` 当成 `len(ExtType+ExtFlags+ExtData)`，即 `ExtData = ExtLen-2`。
2. 真实 type 4 几乎总带 signed-with-ed25519-key（ExtLen=32）。解析会少吃 2 字节，签名窗口错位，验签必失败。
3. `ValidateRelayIdentity` 把 type 4 的 `CertifiedKey`（signing key）当成 identity，与 microdescriptor `id ed25519` 比对会错。
4. 已知类型解析失败被吞掉，`ValidateSignatures` 跳过 `Ed25519Cert==nil`，可能静默放过。

## 最终选择

与 **cert-spec + Arti** 对齐（并与能连上 mainnet 的 C Tor 行为一致）：

- `ExtLen = len(ExtData)`
- 验签用解析时保存的原始 `SignedBytes`，无 prefix
- identity 来自 type 7，其次 type 4 的 signed-with-ed25519-key
- type 4/5/6/7 解析失败为硬错误
- type 4 必须由 type 7 identity 验签；扩展中的 key 必须与之相同

type 7 的 RSA 签名（对照 type 2）本轮尚未强制校验，记为后续 gap。
