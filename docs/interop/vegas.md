# FlowCtrl=2 TOR_VEGAS 互操作

**日期**：2026-08-19

对照：

- Spec：https://spec.torproject.org/proposals/324-rtt-congestion-control.html §3.3
- C Tor：`src/core/or/congestion_control_vegas.c`、`congestion_control_common.c`
- 共识 params：`cc_vegas_*_exit`、`cc_cwnd_*`、`cc_sscap_exit`（已验签 `params` 行）

## 协商

ntor-v3 `CC_FIELD_REQUEST` / `CC_FIELD_RESPONSE` 只交换 `sendme_inc`（mainnet 常见 31）。
`cwnd` 初值与 Vegas 阈值来自共识，不是握手字段。

## 算法要点（与 C Tor 同一套取整）

- RTT：触发 SENDME 的那一格 DATA 的发出时刻到 SENDME 到达。
- N-EWMA：`(rtt*2 + prev*(N-1)) / (N+1)`，Slow Start 用 `cc_ewma_ss`（默认 2）。
- Clock stall：RTT≤0 或（已出 SS 且偏离 EWMA 5000 倍）不更新 cwnd，仍减 `inflight`。
- BDP：`cwnd * min_rtt / ewma_rtt`（Vegas 使用 cwnd 估计器）。
- `queue_use = max(cwnd - BDP, 0)`
- Slow Start：`queue_use < gamma` 且窗口满时按 RFC3742 Limited Slow Start 增加；否则 `cwnd = BDP + gamma` 并退出。
- 拥塞避免：每 `CWND_UPDATE_RATE` 个 SENDME 一次。`>delta` 降到 `BDP+delta-inc`；`>beta` 或 orconn 阻塞减 `cc_cwnd_inc`；窗口满且 `<alpha` 才加窗。
- orconn_blocked：`Connection.WriteBlocked()`（发送排队 >1 或最近 TLS 写出 ≥25ms）。`processCircuitSendme` 采样进 `vegas.blockedChan`。纯 Go。
- 发送额度：`package_window = max(cwnd - inflight, 0)`。不得再用「收到 SENDME 就 +sendme_inc」。

## 默认值（共识未列出时）

| 参数 | 值 | 来源 |
|------|----|------|
| cc_cwnd_init / min | 124 | C Tor `4*TLS_RECORD_MAX_CELLS` |
| cc_cwnd_inc | 1 | 2026-08 共识 |
| cc_cwnd_inc_rate | 31 | 共识 / C Tor |
| cc_vegas_alpha/gamma_exit | 186 | `3*OUTBUF_CELLS` |
| cc_vegas_beta_exit | 248 | `4*OUTBUF_CELLS`（共识常省略） |
| cc_vegas_delta_exit | 310 | 共识 |
| cc_sscap_exit | 600 | 共识 |
| cc_cwnd_full_gap / minpct | 4 / 25 | 共识 |

客户端走 Exit 电路，用 `*_exit` 阈值，不用 onion/sbws。

## gotor

- `pkg/circuit/ccparams.go`：解析 / 默认
- `pkg/circuit/vegas.go`：状态机
- `pkg/circuit/sendme.go`：SENDME v1 digest 仍强制校验，然后跑 Vegas
- `pkg/directory.Client.LastConsensusParams()`：验签成功后缓存 `params`
- `pkg/client` 建路前 `builder.SetCCParams(...)`

## 真实网络（2026-08-19）

`TestRealFlowControlSoak`：SOCKS5 重复拉取 `www.torproject.org`，合计 **1059120** 字节。

- Guard `rafsnicesrelay` → Middle `janina1` → Exit `NTH66R5`
- 三跳均为 ntor-v3 + `FlowCtrl=2` `sendme_inc=31`
- 电路未 DESTROY，SENDME v1 digest 仍强制校验

## 禁止

- 把「已协商 sendme_inc」写成 Vegas 已完成（必须有状态机 + 真实验收）
- 为过测试关掉 SENDME v1 digest
- 未协商成功时偷偷回退固定窗口还宣称 FlowCtrl=2 WORKING
