# ntor-v3 互操作

**日期**：2026-08-19

## 问题

现行 tor-spec 写明：客户端有扩展要发时 **必须** 用 ntor-v3（HTYPE `0x0003`）。
现代 C Tor / Arti 总会带 `CC_FIELD_REQUEST`，因此实际上 **总是** 走 ntor-v3。
经典 ntor `0x0002` 仍被 relay 接受，但已不是最新客户端路径。

主身份是 **32 字节 Ed25519**（`KP_relayid_ed`），不是 RSA-1024。RSA 只留在共识指纹 / 经典 ntor NODEID / CERTS type 2。

## Tor Spec

https://spec.torproject.org/tor-spec/create-created-cells.html

- `PROTOID = "ntor3-curve25519-sha3_256-1"`
- `H(s,t) = SHA3_256(ENCAP(t) || s)`
- `MAC(k,msg,t) = SHA3_256(ENCAP(t) || ENCAP(k) || msg)`
- `KDF(s,t) = SHAKE256(ENCAP(t) || s)`
- `ENC = AES-256-CTR`，IV 全零
- `ENCAP(s) = htonll(len(s)) || s`
- 电路密钥：`KDF_final(ntor_key_seed)` 先取出 32 字节 ENC_KEY，其后 72 字节是 Df/Db/Kf/Kb
- 扩展：`N_EXTENSIONS || (TYPE LEN DATA)*`
  - type 1 `CC_FIELD_REQUEST`（空体）
  - type 2 `CC_FIELD_RESPONSE`（1 字节 `sendme_inc`）
  - type 3 `subproto_request`（proposal 346；见 `docs/interop/subproto.md`）。生产暂不发送。

Relay 宣告 `Relay=4` 才接受 ntor-v3。`FlowCtrl=2` 才协商拥塞控制。

## C Tor / Arti

- C Tor：`src/core/crypto/onion_ntor_v3.c`（Tor 0.5.x 仍用此路径）
- Arti：`crates/tor-proto/src/crypto/handshake/ntor_v3.rs`
- 普通电路扩展的 verification 必须是 `"circuit extend"`（14 字节，无 NUL）。空串会导致服务端 MAC 失败并 DESTROY reason=1。
- 官方向量来自 proposal 332 X.2（已在 `TestNtorV3OfficialVector` 对齐）

## gotor 行为

- 默认：具备 Ed25519 + ntor onion key，且 `pr` 未禁止 `Relay=4` 时，CREATE2/EXTEND2 用 `0x0003`
- `FlowCtrl=2` 时发送 `CC_FIELD_REQUEST`；收到 `sendme_inc` 后启用 TOR_VEGAS（初始 cwnd=`cc_cwnd_init`，C Tor 默认 124）
- 未宣告 FlowCtrl=2 时不请求 CC，继续经典 SENDME v1（间隔 100）
- 缺 Ed25519 或 `Relay<4` 时回退经典 ntor

## 验收（2026-08-19）

- 单测：proposal 332 官方向量（`TestNtorV3OfficialVector`）
- 真实网络（`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration`）：
  - `TestRealNtorV3` / `TestRealGuardCreate2`：HTYPE=3，协商 `FlowCtrl=2` `sendme_inc=31`
  - `TestRealThreeHopCircuit`：三跳均为 ntor-v3 + CC，电路 READY
  - `TestRealCheckTorProject`：BiggerBetter → forest38 → Quetzalcoatl，`IsTor=true`，ExitIP=`185.244.192.184`
  - `TestRealFlowControlSoak`：1059120 字节，电路未 DESTROY（FlowCtrl=2 Vegas）
  - `TestRealRelayResolve`：exit DFRI149，`www.torproject.org` → `116.202.120.166` + IPv6
