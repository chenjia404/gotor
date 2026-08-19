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
**当前 `ImplementedNegotiableCaps()` 为空，生产路径不会发出 type 3。**

## gotor

- `pkg/crypto/subproto.go`：编解码、排序、表校验、选择
- `pkg/crypto/ntorv3.go`：`NtorV3ExtSubprotoRequest = 3`，`EncodeNtorV3ClientMsg`
- `pkg/directory`：`SupportsSubprotoRequest`（`Relay=5`）
- `pkg/circuit/extension.go`：CREATE2/EXTEND2 的 CM 走 `EncodeNtorV3ClientMsg`

## 真实网络（2026-08-19）

`TestRealGuardCreate2` / `TestRealNtorV3`：Guard `SENDNOOSEplz`，HTYPE=3，`FlowCtrl=2` `sendme_inc=31`。未出现 type 3 请求日志，CREATE2 成功。

## 禁止

- 在 CGO 未实现时请求 `Relay=6`
- 对未宣告 `Relay=5` 的节点发 type 3
- 把「能编码 [02 06]」写成 CGO 或 Relay=5 已在真实网络启用
