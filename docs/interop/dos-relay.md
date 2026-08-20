# 中继官方级 DoS（最小切片）

**日期**：2026-08-20  
**状态**：PARTIAL（官方 `DoS*` 键 + CREATE2/连接接线；**无**共识参数、**无**连接速率桶）

对照：C Tor `src/core/or/dos.c`、man `DoSCircuitCreation*` / `DoSConnection*` / `DoSRefuseSingleHopClient`。

## 本切片已做

- 解析官方 torrc 键，**不改** `ConnLimit` 语义（全局仍由 OR 监听 `maxConnections` 管）。
- `Enabled=auto`（默认）且无共识 `DoS*` 参数时视为**关**，不假装已启用。
- 显式 `DoSConnectionEnabled 1`：每 IP 并发 OR 连接上限（默认 100），在 accept 后、TLS 前拒绝。
- 显式 `DoSCircuitCreationEnabled 1`：该 IP 并发连接 ≥ `MinConnections`（默认 3）后，对 CREATE2 套令牌桶（Rate/Burst，默认 3/90）；桶空则进入 `DefenseTimePeriod`（默认 1h）一律拒绝，DESTROY `RESOURCELIMIT`。
- `DoSRefuseSingleHopClient 1`：从未 EXTEND 的电路上 `BEGIN` / `BEGIN_DIR` / `RESOLVE` 则 DESTROY。
- 入站 OR 与 `CircuitHandler.handleCreate2` 已接线（不再只停在未接入的 `ProtectionManager`）。

## 明确未做

- 共识参数 `DoSCircuitCreationEnabled` 等（auto 跟共识）
- `DoSConnectionConnectRate` / `Burst` / `ConnectDefenseTimePeriod`
- `DoSStreamCreation*`
- 按「是否已 AUTHENTICATE 为中继」区分单跳（本切片只看是否 EXTEND 过）
- `DoSCircuitCreationDefenseType` 除拒绝以外的类型
- 宣称「已对齐完整 dos.c」或审计文档里的「100% DoS」

## 禁止

- 只加全局 `MaxConnections` / `ConnLimit` 就写「官方级 DoS」
- 默认 auto 却按已开启防御来宣传
- 改已有 `ConnLimit` 键语义
