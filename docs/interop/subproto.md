# ntor-v3 `subproto_request`（Relay=5 / proposal 346）

**日期**：2026-08-19

对照：

- Spec：https://spec.torproject.org/tor-spec/create-created-cells.html （Extension handshake: Subprotocol request）
- Proposal：https://spec.torproject.org/proposals/346-protovers-again.html
- C Tor：`protover.h` 的 `protocol_type_t`；握手扩展 type 3

## 格式

ntor-v3 / hs-ntor 共用扩展 type **3**。DATA 是若干：

```
protocol_id   [1]
cap_number    [1]
```

按 `protocol_id` 再 `cap_number` 升序。Relay=6（CGO）编码为 **`[02 06]`**。

协议编号：Link=0 LinkAuth=1 **Relay=2** DirCache=3 … FlowCtrl=11 Conflux=12。

## 选择条件（必须同时满足）

1. 能力在现行协商表里（目前只有 `RELAY_CRYPT_CGO` / Relay=6）
2. 对端宣告 `Relay=5`（否则不理解 type 3）
3. 对端宣告该能力（否则对端 **DESTROY**）
4. **本端已经实现**该能力

第 4 条是硬约束：对端若接受 `[02 06]` 会改用 CGO，本端若仍走 AES-CTR-SHA1 会拆路。  
**当前 `ImplementedNegotiableCaps()` 含 CGO。** 对端同时宣告 `Relay=5`、`Relay=6`、`FlowCtrl=2` 时生产路径会发出 type 3 `[02 06]`。

## gotor

- `pkg/crypto/subproto.go`：编解码、排序、表校验、选择
- `pkg/crypto/ntorv3.go`：`NtorV3ExtSubprotoRequest = 3`，`EncodeNtorV3ClientMsg`
- `pkg/directory`：`SupportsSubprotoRequest`（`Relay=5`）
- `pkg/circuit/extension.go`：CREATE2/EXTEND2 的 CM 走 `EncodeNtorV3ClientMsg`

## 禁止

- 对未宣告 `Relay=5` / `Relay=6` 的节点发 type 3
- 请求 CGO 后仍按 72 字节 AES-CTR 派生密钥
- 把「能编码 [02 06]」单独写成已在真实网络启用 CGO（CGO 本身的验收见 `docs/interop/cgo.md`）
