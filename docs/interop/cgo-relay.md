# 中继侧 CGO（Relay=6）

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；描述符未宣告 `Relay=5-6`）

对照：[proposal 359](https://spec.torproject.org/proposals/359-cgo-redux.html)、C Tor `relay_crypto_cgo.c`（`CGO_AES_BITS=128`）。

## 本切片已做

- ntor-v3 服务端解密 CM；type 3 DATA 含 `[02 06]` 则 KDF 160 字节（fwd 80 + back 80），与客户端 `SetKeyMaterialLen(160)` 对齐。
- 畸形 type 3 失败握手，不得静默回退 72 字节 tor1。
- 中继用 ENC_UIV（`NewCGORelayPairFromKeyMaterial`）；客户端仍 DEC_UIV。
- 入站 `RelayForward`，AD 为链路命令 RELAY(3) / RELAY_EARLY(9)；本跳识别后按 v1 解码。
- 本跳发出用 v1 编码 + `RelayOriginate`；中间跳回程 `RelayBackward`（不 originate）。
- 出口 `RELAY_DATA` 在 CGO 电路按 488 字节分片（v1 头 21）。

## 明确未做

- 描述符 `proto` 写 `Relay=5-6`（缺真网被请求证据）
- 中继侧 SENDME v1（16 字节 CGO tag）与完整 Vegas
- 真网官方客户端对本中继发出 type 3 并完成 CGO 电路的观察

## 禁止

- 未协商成功却宣称 CGO
- AES-256 当 CGO
- 把离线往返单测写成「已被真网选为 CGO hop」
