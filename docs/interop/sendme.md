# SENDME 互操作

**日期**：2026-08-19

对照：

- Spec：https://spec.torproject.org/tor-spec/flow-control.html
- C Tor：`src/core/or/sendme.c`
- Arti：`crates/tor-proto` `SendmeValidator` / `tor1::last_sendme_tag`

## 电路级（StreamID=0）

现代共识 `sendme_emit_min_version` / `sendme_accept_min_version` 为 1。空 payload（v0）会被 exit 拆路。

```
VERSION   [1]  = 0x01
DATA_LEN  [2]  = 20
DIGEST    [20] = 触发该 SENDME 的 DATA cell 之后的完整滚动 SHA-1
```

DIGEST 是 **20 字节**，不是 relay cell header 里的 4 字节 digest 字段。

记录时机：发出 DATA 后 `package_window % 100 == 0`（1000→900、800…）。
发送时机：收到 DATA 后 `deliver_window` 降到 900、800…，DIGEST 取**刚收到的那一格** cell 的 backward digest。

不匹配或 unexpected SENDME：拆路（TORPROTOCOL）。

## 流级（StreamID≠0）

body 仍为空，接收方忽略。窗口 500，每 50 cell +50。

## gotor

- `pkg/cell/sendme.go`：编解码
- `pkg/circuit/sendme.go`：FIFO 校验 / 发出 v1
- DATA cell 未用 padding 填随机字节（spec：每个 increment 窗口内 digest 不可预测）
