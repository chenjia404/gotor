# Relay=6 CGO（Counter Galois Onion）

**日期**：2026-08-19

对照：

- Proposal 359：https://spec.torproject.org/proposals/359-cgo-redux.html
- C Tor：`src/core/crypto/relay_crypto_cgo.c`、`relay_crypto.c`（`CGO_AES_BITS 128`）
- 官方向量：C Tor `src/test/cgo_vectors.inc`（python 参考实现，不是本仓库重生）

## 密钥

C Tor 生产用 **AES-128**，不是 AES-256。

```
每方向：UIV key 64 || N 16 = 80
双向：160
ntor-v3 KDF_final 跳过 32 字节 ENC_KEY 后取 160 字节
```

`relay_crypto_key_material_len(CGO) = cgo_key_material_len(128) * 2 = 160`。

proposal 359 文中的 KH(20) **没有**出现在 C Tor 的 CGO key material 里。

## 算法

- UH = POLYVAL（RFC 8452）
- ET = LRW2：`UH(KU,T) XOR AES(KB, M XOR UH(KU,T))`
- PRF：`CTR(K, MASK(POLYVAL(B,T)) + t*31)`，MASK 清掉末字节低 6 位
- 客户端只用 `DEC_UIV`；中继只用 `ENC_UIV`
- AD = 链路命令 RELAY(3) / RELAY_EARLY(9)

## v1 cell（C Tor relay_msg.c）

```
[0:16]   CGO tag
[16]     command
[17:19]  length（仅 data）
[19:21]  stream_id（BEGIN/DATA/END/CONNECTED/RESOLVE/RESOLVED/BEGIN_DIR/XON/XOFF）
其后 data，再 4 字节 0 + 随机
```

带 stream_id 的命令最大 data 是 **488**（509-21），不是 v0 的 498。TLS ClientHello 经常超过 488，必须按 v1 上限分片。

## SENDME

识别 hop 后的 16 字节 tag T，放进**电路级** SENDME v1，`DATA_LEN=16`。

v1 的 `relay_cmd_expects_streamid_in_v1` **不含** SENDME，因此 CGO 电路不发流级 SENDME，也不减流行控制窗口。流控改由 FlowCtrl=2 电路级 SENDME（以及日后的 XON/XOFF）承担。

## 协商

ntor-v3 type 3 请求 `[02 06]`，且仅当对端 `Relay=5` ∧ `Relay=6` ∧ `FlowCtrl=2`。
请求后必须用 160 字节 KDF 建 CGO hop；**禁止**再按 72 字节切回 AES-CTR。

## 真实网络

待 `TOR_INTEGRATION_TEST=1` 跑 CREATE2 / 3-hop / `IsTor=true`。
未通过前状态为 UNVERIFIED。
