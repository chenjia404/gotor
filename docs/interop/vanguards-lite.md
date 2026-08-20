# 客户端 vanguards-lite（最小切片）

**日期**：2026-08-20  
**状态**：PARTIAL（客户端 HS 电路固定 L2 并落盘；**无** L3、**无**托管侧、**无**共识参数）

对照：[vanguards-spec Vanguards-lite](https://spec.torproject.org/vanguards-spec/vanguards-lite.html)、C Tor `guard-hs-l2-number=4` / `lifetime-min=1d` / `lifetime-max=12d`。

## 本切片已做

- HS 电路（INTRO / REND / HSDir BEGIN_DIR）走 **L1 入口 → 固定 L2 → 目标**，不再每次随机中间跳。
- L2 默认 4 个，从 `UsableAsGuard` 节点选取；寿命均匀随机 1–12 天。
- 重启后从 `DataDirectory/state` 的自有键 `GotorHSLayer2Guards` 恢复。**不改**官方 `Guard` 行语义。
- L1 优先用已持久化的入口 Guard（`GuardManager`）；已升为 L1 的节点会从 L2 剔除并补员，避免 L1/L2 重叠。
- 已注入 `VanguardSet` 时选路失败则关闭，**不**退回随机中间跳。
- 当前电路目标碰巧是某 L2 时只在本条避开，不从全局集合剔除。
- L1/L2/目标三跳拒绝同家族；与目标同家族的持久入口会被跳过，无法避开则关闭。
- `DataDirectory/state` 与入口 Guard 落盘共用进程内锁，并经 `state.lock` flock 读改写。
- `AvoidDiskWrites` 时不落盘。

## 明确未做

- 完整 vanguards 插件的 L3 层
- 共识参数 `guard-hs-l2-*` / `guard-hs-l3-*`
- 洋葱**托管**侧 intro/rend 电路的 L2 固定
- 与 C Tor 完全相同的 state `Guard in=...` 行格式（本切片用独立键以免误改官方入口）

## 禁止

- 随机多跳冒充 vanguards
- 无持久化状态就宣称已防护
- 把本切片写成完整 vanguards 或 L3
