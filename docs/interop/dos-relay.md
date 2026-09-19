# 中继官方级 DoS（最小切片）

**日期**：2026-08-20  
**状态**：PARTIAL（官方 `DoS*` 键 + CREATE2/连接接线 + **auto 跟共识** + **ConnectRate/Burst** + **StreamCreation** + **AUTHENTICATE 单跳区分** + **CircuitCreationDefenseType** + **共识 nodelist 核对身份**）

对照：C Tor `src/core/or/dos.c`、man `DoSCircuitCreation*` / `DoSConnection*` / `DoSStreamCreation*` / `DoSRefuseSingleHopClient`。

## 本切片已做

- 解析官方 torrc 键，**不改** `ConnLimit` 语义（全局仍由 OR 监听 `maxConnections` 管）。
- `Enabled=auto`（默认）且无共识 `DoS*` 参数时视为**关**，不假装已启用。显式 0/1 不被共识覆盖。
- 显式 `DoSConnectionEnabled 1`：每 IP 并发 OR 连接上限（默认 100），在 accept 后、TLS 前拒绝。
- 显式 `DoSCircuitCreationEnabled 1`：该 IP 并发连接 ≥ `MinConnections`（默认 3）后，对 CREATE2 套令牌桶（Rate/Burst，默认 3/90）。桶空按 `DoSCircuitCreationDefenseType`：1 放行且不进防御窗；2（缺省）进入 `DefenseTimePeriod`（默认 1h）拒绝，DESTROY `RESOURCELIMIT`。
- `DoSRefuseSingleHopClient 1`：从未**成功** EXTEND（下一跳已登记）的电路上 `BEGIN` / `BEGIN_DIR` / `RESOLVE` 则 DESTROY。截断或失败的 EXTEND2 不打标。入站已 **AUTHENTICATE**（LinkAuth=3）且共识 nodelist 收录该 RSA 指纹或 Ed25519 身份的中继视为非客户端，单跳放行。尚未注入共识时 fail-open。BEGIN 时再查。
- 入站 OR 与 `CircuitHandler.handleCreate2` 已接线（不再只停在未接入的 `ProtectionManager`）。
- **2026-09-19**：`Enabled=auto` 读共识 `DoSCircuitCreationEnabled` / `DoSConnectionEnabled`（0–1，缺省 0）。`DoSConnectionConnectRate` / `Burst` / `ConnectDefenseTimePeriod`：torrc `0` 跟共识（缺省 20/40/24h）；桶空进入防御窗。gotor 拉共识后 `SetDoSConsensusParams`。
- **2026-09-19**：`DoSStreamCreationEnabled` auto 跟共识；每电路 `BEGIN`/`BEGIN_DIR`/`RESOLVE` 令牌桶（缺省 100/300）。`DefenseType`：1 无动作、2 `RELAY_END` MISC、3 `DESTROY` RESOURCELIMIT（缺省 2）。无 StreamCreation 防御时间窗（C Tor 也没有）。
- **2026-09-19**：`DoSRefuseSingleHopClient` 对已 AUTHENTICATE 且共识 nodelist 收录的入站中继放行单跳 BEGIN；普通客户端仍须成功 EXTEND。`SetHSDirRing` 同时注入身份（dirCache 为 nil 时仍注入）。空注入保留上一份表。

- **2026-09-19**：`DoSCircuitCreationDefenseType` torrc 0 跟共识（缺省 2=拒绝 CREATE2）；1=无动作（桶空仍放行，不进防御窗）。显式值不被共识覆盖。

## 明确未做

- 宣称「已对齐完整 dos.c」或审计文档里的「100% DoS」（无 geoip、无其余未接线防御/统计）

## 禁止

- 只加全局 `MaxConnections` / `ConnLimit` 就写「官方级 DoS」
- 默认 auto 却按已开启防御来宣传
- 改已有 `ConnLimit` 键语义
