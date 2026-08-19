# Circuit padding（Padding=2 / proposal 302）

**状态**：PARTIAL（2026-08-19：协商+HS setup 表+运行时+**直方图延迟定时器**；onion AfterIntroduce1 已接线）

对照：

- [padding-spec circuit-level-padding](https://spec.torproject.org/padding-spec/circuit-level-padding.html)
- proposal 302；C Tor `circuitpadding_machines.c` / `circuitpadding_machines.h`

## 已实现（纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/circuit/circpad.go` | PADDING_NEGOTIATE/NEGOTIATED 8 字节编解码；HS setup 状态表 |
| `pkg/circuit/circpad_runtime.go` | `CircpadController`；intro/rend 状态转移 |
| `pkg/circuit/circuit.go` | `SendRelayCellToHop`；`StartHSSetupPadding` |
| `pkg/client` | 共识后 `refreshCircpadConfig`；`StartHSSetupPaddingOn` |
| `pkg/circuit/padding_machine.go` | 兼容包装；`CIRC_SETUP=1`、`STOP=1`/`START=2` |

### 协商单元

- `STOP=1`、`START=2`
- `machine_type=CIRCPAD_MACHINE_CIRC_SETUP(1)`
- `machine_ctr` u32 网络序；总长 **8** 字节

### HS setup 运行时

- `ClientHideIntroCircuits` / `ClientHideRendCircuits` / `RelayHideIntroCircuits`
- Intro DROPs **7–10**；`circpad_padding_disabled` 禁用
- 协商发往 **第二跳**（`encryptOnion` dest=1）
- 错误 ctr 忽略；ERR 结束机

## 直方图延迟

- `CircpadHistogram.SampleDelay`：token 权重选 bin，`[edge[i], edge[i+1])` µs 均匀采样
- 客户端 rend：`[0, 1ms)`；中继 intro：`[1, 10ms)`（对照 C Tor）
- `SchedulePaddingAfterNegotiate`：negotiate 后 `time.AfterFunc` 发 `RELAY_DROP`

## 未做

- Token removal / 可变直方图拷贝
- circpad 真实验收（中继侧需对端 Padding=2）

## 禁止

- 发明与 C Tor 状态表不符的随机 padding 并宣称 Padding=2
- 3 字节旧 negotiate 载荷
- CGO
