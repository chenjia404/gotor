# Conflux=1（proposal 329）

**日期**：2026-08-19

对照：

- Proposal 329：https://spec.torproject.org/proposals/329-traffic-splitting.html
- C Tor：`conflux.c`、`conflux_cell.c`、`conflux_pool.c`
- Arti：`tor-cell` `relaycell/conflux.rs`

## 命令

| 命令 | 号 | 方向 | stream_id |
|------|----|------|-----------|
| `RELAY_CONFLUX_LINK` | 19 | 客户端 → Exit，每条腿各一 | 无（v1 也不带） |
| `RELAY_CONFLUX_LINKED` | 20 | Exit → 客户端 | 无 |
| `RELAY_CONFLUX_LINKED_ACK` | 21 | 客户端 → Exit（给 Exit 测 RTT） | 无 |
| `RELAY_CONFLUX_SWITCH` | 22 | 换腿时发在**新腿**上 | 无 |

## LINK / LINKED 负载（50 字节，大端）

```
VERSION           [1]   必须 0x01
NONCE             [32]  两条腿相同；禁止写日志/落盘
LAST_SEQNO_SENT   [8]   初次为 0
LAST_SEQNO_RECV   [8]   初次为 0
DESIRED_UX        [1]   本客户端发 3（HIGH_THROUGHPUT）
```

SWITCH：`SeqNum [4]` 相对序号 = 全局已发绝对序号 − 目标腿上次已发绝对序号。

## 选择与握手

- 两条腿 Guard/Middle/Exit **均**宣告 `Conflux=1` **或** `Conflux=2`（proposal 346：号是 flag；mainnet 常见只写 `Conflux=2`）。
- 两条腿都必须已协商 **FlowCtrl=2**；否则关第二腿，不标 Conflux。
- 同一 Exit，不同 Guard / Middle（按身份键，不是 family/IP）。
- 每条腿发 LINK → 等 LINKED → 回 LINKED_ACK。任一条 LINKED 超时则两条都关。
- 发送用 **LowRTT**（HIGH_THROUGHPUT）：有窗的腿里选 RTT 最低的。
- 计入序号：BEGIN / DATA / END / CONNECTED / RESOLVE / RESOLVED / BEGIN_DIR / XON / XOFF。
- 电路级 SENDME 仍按腿；DATA 一到就计窗。
- 不做完整 resumption；任一腿关闭则拆套。

## 禁止

- 把未完成 LINK 的单电路标成 Conflux。
- 未协商 FlowCtrl=2 却发 LINK。
- 日志或磁盘写出 LINK nonce。
- 用 C 库 / CGO。

## 真实网络

尚未跑通。验收：日志有 LINK/LINKED/LINKED_ACK；两腿不同 Guard/Middle、同一 Exit；SOCKS `IsTor=true`。
