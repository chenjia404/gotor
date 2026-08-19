# Exit policy（`p` / `p6` / 完整 accept-reject）

**日期**：2026-08-19

对照：

- dir-spec computing-microdescriptors：`p` IPv4 摘要；`p6` IPv6 摘要；**缺 p6 ≡ `p6 reject 1-65535`**
- dir-spec server-descriptor-format：`accept`/`reject` exitpattern；无匹配则接受；`ipv6-policy` 缺行 ≡ `reject 1-65535`
- C Tor：`compare_tor_addr_to_node_policy` 对 IPv6 只用 short policy（p6 / ipv6-policy），不用 IPv4 `*` 规则去放行 IPv6

## 实现（100% 纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/directory/exitpolicy.go` | 解析 `p` / `p6` / `ipv6-policy`；`CanExitTo` 按地址族分流 |
| `pkg/directory/exitrules.go` | 完整 `accept`/`reject` 列表（CIDR、点分掩码、`[IPv6]/bits`、`*`/`*4`/`*6`） |
| `pkg/directory/microdesc.go` | microdescriptor 读 `p6` |
| `pkg/path` | `ExitTarget` + `SelectPathFor`；IPv6 字面量只选 p6 放行的 exit |
| `pkg/circuit/exitfilter.go` | 建路后绑定 Exit；未绑定不得盲放行 IPv6 |
| `pkg/pool` `GetIf` / SOCKS | 池中挑允许该目标的电路；否则按目标再建 |

## 匹配规则

- IPv4 / 主机名：完整规则（若有）或 `p`；都没有则退回 Exit flag
- IPv6：完整规则里的 IPv6 项（若有）或 `p6`；**都没有则拒绝**
- `*` / `*4` 只匹配 IPv4；不得据此放行 IPv6
- 连接端口 0 永远拒绝
- 完整规则无匹配 → 接受（dir-spec）；摘要语义仍是 accept 列表 / reject 列表

## 禁止

- 用 IPv4 `p` 或 Exit flag 宣称 IPv6 可出口
- 缺 p6 时对 IPv6 字面量发 RELAY_BEGIN
- 为过测试把缺 p6 当成 accept
- C 库 / `import "C"` / CGO

## 真实验收

`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration -run TestRealExitPolicyP6`

未跑过真实 microdesc + 选路之前，本项保持 PARTIAL，不得标 WORKING。
