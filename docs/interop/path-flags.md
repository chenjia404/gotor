# 选路标志：Fast / MiddleOnly / BadExit

**日期**：2026-08-19  
**状态**：PARTIAL（选路强制；未跑真实网络）

对照：

- path-spec [path-selection-constraints](https://spec.torproject.org/path-spec/path-selection-constraints.html)（Universal constraints）
- proposal [334-middle-only-flag](https://spec.torproject.org/proposals/334-middle-only-flag.html)

## 实现（100% 纯 Go）

只面向**现行**非测试电路。不保留旧版「允许非 Fast」路径。

| 位置 | 要求 |
|------|------|
| 每一跳 | `Running` + `Valid` + `Fast` |
| Guard | 另需 `Guard` + `Stable`，且不得 `MiddleOnly` |
| Exit | 不得 `MiddleOnly`、不得 `BadExit` |
| Middle | `MiddleOnly` 可以 |

共识入库时 Guard 列表已按 `UsableAsGuard` 过滤。`selectGuard` / `selectMiddle` / `selectExitFor` / Conflux 选路再验一次。持久化 Guard 若丢失 Fast 或被标 `MiddleOnly`，不得再用。

标志来自共识 `s` 行，选路时已有，无需等 microdesc。

## 禁止

- 把非 Fast 继电器放进非测试电路
- 把 MiddleOnly 当 Guard 或 Exit
- 把 BadExit 当 Exit
- 为过测试去掉 Fast 要求
- C 库 / CGO
