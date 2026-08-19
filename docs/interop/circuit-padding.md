# Circuit padding（Padding=2 / proposal 302）

**日期**：2026-08-19  
**状态**：PARTIAL（协商单元与 HS setup 状态表已对齐 C Tor；onion 建路接线与真实验收待 Phase 4）

对照：

- [padding-spec circuit-level-padding](https://spec.torproject.org/padding-spec/circuit-level-padding.html)
- proposal 302；C Tor `circuitpadding_machines.c` / `circuitpadding_machines.h`

## 已实现（纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/circuit/circpad.go` | PADDING_NEGOTIATE/NEGOTIATED 8 字节编解码；HS setup 状态表 |
| `pkg/circuit/padding_machine.go` | 兼容包装；`CIRC_SETUP=1`、`STOP=1`/`START=2` |

### 协商单元（修正）

- `STOP=1`、`START=2`（旧实现曾写反）
- `machine_type=CIRCPAD_MACHINE_CIRC_SETUP(1)`
- `machine_ctr` u32 网络序；总长 **8** 字节（含 unused）
- negotiated：`response` 字段 `OK=1` / `ERR=2`

### HS setup 状态表

- `ClientHideIntroCircuits` / `RelayHideIntroCircuits`：INTRO DROPs **7–10**
- `ClientHideRendCircuits`：对照 C Tor rend 机转移
- `CircpadPaddingDisabled`：读共识 `circpad_padding_disabled`

## 未接线

- Onion INTRODUCE1 后自动发 negotiate（需 Phase 4 hs-ntor）
- 中继侧发 DROP 的运行时（客户端库只协商；靠对端 Padding=2）
- 直方图延迟采样完整 WTF-PAD 运行时

## 禁止

- 发明与 C Tor 状态表不符的随机 padding 并宣称 Padding=2
- 3 字节旧 negotiate 载荷
- CGO
