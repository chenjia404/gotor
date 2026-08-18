# ntor 互操作记录

## Tor Spec

- 文档：https://spec.torproject.org/tor-spec/create-created-cells.html
- `NODEID = SHA1(DER(KP_relayid_rsa))`，**20 字节**
- `H(x,t) = HMAC-SHA256(key=t, msg=x)`
- `AUTH = H(verify | ID | B | Y | X | PROTOID | "Server", t_mac)`
- 电路密钥：`KDF-RFC5869(IKM=KEY_SEED, salt=t_key, info=m_expand)` → 72 字节

## C Tor

- `src/core/crypto/onion_ntor.c`
- `ID` 为 `DIGEST_LEN`（20）
- `crypto_hmac_sha256` + `crypto_expand_key_material_rfc5869_sha256(key_seed, t_key, m_expand)`

## Arti

- `crates/tor-proto/src/crypto/handshake/ntor.rs`
- 同样使用 20-byte RSA digest 与 HMAC-SHA256，再 HKDF expand

## gotor 原行为（错误）

- NODEID 取 Ed25519 公钥前 20 字节
- `secret_input` 使用 32 字节 identity
- `AUTH` 直接等于 `HKDF(secret_input, salt=nil, info=t_verify)`
- 密钥直接 `HKDF(secret_input, salt=nil, info=t_key)`

这与 C Tor / Arti **无法互操作**。仓库里旧 testdata 是按该错误算法自生成的，并非官方向量。

## 最终选择

按 Tor Spec / C Tor / Arti 实现 HMAC + 20-byte NODEID。

禁止：

- Ed25519 截断当 NODEID
- 全零 key fallback
