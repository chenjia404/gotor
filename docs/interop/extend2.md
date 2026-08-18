# EXTEND2 互操作（进行中）

**日期**：2026-08-18

## 已验证

Guard CREATE2 / ntor / CREATED2 在真实 Tor Network 成功（72 字节密钥）。
Link handshake（VERSIONS v5 + CERTS 验签 + NETINFO）成功。

## 当前失败

发送 EXTEND2（RELAY_EARLY）后，Guard 立即 `DESTROY reason=1`（TORPROTOCOL）。

不是超时、不是连接失败。约 90ms 内本地协议拒绝。

## Tor Spec

https://spec.torproject.org/tor-spec/create-created-cells.html

EXTEND2 必须放在 RELAY_EARLY，StreamID=0：

```
NSPEC [1]
NSPEC × { LSTYPE[1] LSLEN[1] LSPEC[LSLEN] }
HTYPE [2]  = 0x0002 (ntor)
HLEN  [2]
HDATA [HLEN]  = NODEID(20) || KEYID(32) || CLIENT_PK(32)
```

建议 specifier 顺序：`[00]` IPv4、`[02]` RSA 20、`[03]` Ed25519 32、`[01]` IPv6。

RELAY cell Length 必须等于 Data 长度。

## C Tor

`src/feature/relay/circuitbuild_relay.c`：`circuit_extend()`

校验失败会 `circuit_mark_for_close(..., END_CIRC_REASON_TORPROTOCOL)`：

- `extend_cell` 解析失败
- RSA / Ed25519 identity 无效或与 nodelist 不一致
- 无有效 IPv4/IPv6 ORPort
- 要求连回上一跳（RSA 或 Ed25519 相同）
- 电路状态不允许再 extend

连接下一跳失败一般是 `CONNECTFAILED`（reason 6），不是 1。

## Arti

`crates/tor-cell` / `crates/tor-proto`：`LinkSpec` 编码为 type+len+body；ntor HDATA 84 字节。

## gotor 当前行为

- RELAY Length 已按 `len(Data)` 写出（曾为 0，Length 修复后才出现 DESTROY 1，说明 Guard 已识别为 EXTEND2）
- 使用 RELAY_EARLY、StreamID=0、HTYPE=0x0002、HDATA=84
- specifier：IPv4 + RSA + Ed25519

## 下一轮要查

1. 对照 C Tor `extend_cell` 解析，抓一份真实 EXTEND2 hex（不含私钥）
2. Guard nodelist 中的 middle Ed25519 是否与 microdesc `id ed25519` 一致
3. digest / recognized 已能让 Guard 识别命令，重点在 payload 语义
