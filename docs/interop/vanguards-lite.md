# 客户端与托管 vanguards（L2 + L3）

**日期**：2026-09-20  
**状态**：PARTIAL（客户端 HS 电路与托管 intro/rend 固定 L2+L3 并落盘；读共识参数；托管已真网 HTTP 200，未核对 C Tor `Guard in=` 行）

对照：[vanguards-spec Vanguards-lite](https://spec.torproject.org/vanguards-spec/vanguards-lite.html)、[Full Vanguards](https://spec.torproject.org/vanguards-spec/full-vanguards.html)、param-spec `guard-hs-l2-*` / `guard-hs-l3-*` 默认值。

## 本切片已做（2026-08-20 L2）

- HS 电路（INTRO / REND / HSDir BEGIN_DIR）走固定 L2，不再每次随机中间跳。
- L2 默认 4 个，从 `UsableAsGuard` 节点选取；寿命均匀随机 1–12 天。
- 重启后从 `DataDirectory/state` 的自有键 `GotorHSLayer2Guards` 恢复。**不改**官方 `Guard` 行语义。
- L1 优先用已持久化的入口 Guard（`GuardManager`）；已升为 L1 的节点会从 L2 剔除并补员。指纹统一成 40 位 hex。
- 已注入 `VanguardSet` 时选路失败则关闭，**不**退回随机中间跳。
- 当前电路目标碰巧是某 L2 时只在本条避开，不从全局集合剔除。
- L1/L2/目标拒绝同家族；与目标同家族的持久入口会被跳过，无法避开则关闭。
- `AvoidDiskWrites` 时不落盘。

## 本切片已做（2026-09-19 L3）

- 默认再固定 **L3=8**，寿命 1–48 小时，按 spec 的 max(X,X) 抽样。
- HS 电路变为 **L1 → L2 → L3 → 目标** 四跳；`Path.Middle2` 为 L3，SOCKS/Conflux 三跳不受影响。
- `circuit.Builder` 在 `Middle2 != nil` 时多一次 EXTEND2。
- 落盘 `GotorHSLayer3Guards`；L1/L2/L3 互斥；目标碰巧是某 L3 时只在本条避开。
- 四跳家族冲突失败关闭。
- 拉共识后读取 `guard-hs-l2-*` / `guard-hs-l3-*`（数量 1–19 / 1–20；寿命秒；min>max 回退默认）。下一轮选路按新上限补员或裁剪。

## 本切片已做（2026-09-20 托管 intro/rend）

- 托管引言电路末跳必须是引言点（不再 `SelectPath(0)` 随机出口）。
- 托管会合电路与描述符上传 BEGIN_DIR 走同一套 `selectOnionPath`（已注入则 L1→L2→L3→目标，失败关闭）。
- `startConfiguredOnionServices` 把客户端 `VanguardSet` / `GuardManager` 注入 `ServiceConfig`。

## 明确未做

- 与 C Tor 完全相同的 state `Guard in=...` 行格式（本切片用独立键以免误改官方入口）
- 把 L2 寿命改成 Full Vanguards 文档里的 30–60 天（现网 param-spec 默认仍是 lite 的 1–12 天）
- 真网托管上线后的 intro/rend 四跳证据

## 禁止

- 随机多跳冒充 vanguards
- 无持久化状态就宣称已防护
- 把本切片写成插件级完整 vanguards
