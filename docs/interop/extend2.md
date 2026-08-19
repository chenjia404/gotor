# EXTEND2 互操作

**日期**：2026-08-19

## 已验证（真实 Tor Network）

- Guard CREATE2 / ntor-v3（HTYPE `0x0003`）/ CREATED2（先 32 字节 ENC_KEY，再 72 字节电路密钥）
- 经典 ntor `0x0002` 仅作缺 Ed25519 / `Relay<4` 时的回退
- Link handshake（VERSIONS v5 + CERTS 验签 + NETINFO）
- RELAY_DROP 不再触发 DESTROY（digest / AES-CTR 与 Guard 一致）
- Guard → Middle EXTEND2 / EXTENDED2
- Middle → Exit EXTEND2 / EXTENDED2
- 3-hop circuit READY
- SOCKS5 → `https://check.torproject.org/api/ip` 返回 `IsTor=true`

## 曾失败的根因

发送第一个 RELAY（EXTEND2 或 RELAY_DROP）后，Guard 立即 `DESTROY reason=1`。

不是 EXTEND2 specifier 语义，而是电路密钥错误：

`pkg/crypto/ntor.go` 曾对已经 Extract 过的 `KEY_SEED` 再做一次 HKDF-Extract。

- AUTH 只走 HMAC，CREATE2 仍能过
- Df/Db/Kf/Kb 与 Guard 不一致，RELAY 无法 recognized
- 无下一跳 → DESTROY reason=1

对照：

- Spec：https://spec.torproject.org/tor-spec/setting-circuit-keys.html （IKM == secret_input）
- C Tor：`crypto_expand_key_material_rfc5869_sha256(secret_input, t_key, m_expand)`
- Arti：`Ntor1Kdf.derive(secret_input)`

正确：`HKDF-SHA256(IKM=secret_input, salt=t_key, info=m_expand)`  
等价于 `HKDF-Expand(PRK=KEY_SEED, info=m_expand)`。

## EXTEND2 格式（已对照 spec）

```
NSPEC [1]
NSPEC × { LSTYPE[1] LSLEN[1] LSPEC[LSLEN] }
HTYPE [2]  = 0x0002 (ntor)
HLEN  [2]
HDATA [HLEN]  = NODEID(20) || KEYID(32) || CLIENT_PK(32)
```

specifier 顺序：`[00]` IPv4、`[02]` RSA 20、`[03]` Ed25519 32。
RELAY_EARLY、StreamID=0、Length = Data 长度。
