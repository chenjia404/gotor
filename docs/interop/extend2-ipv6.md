# EXTEND2 IPv6（Relay=3）

**日期**：2026-08-19

对照：

- tor-spec create-created-cells：specifier `[01]` TLS-over-TCP IPv6
- 子协议 `RELAY_EXTEND_IPv6`（`Relay=3`）
- dir-spec：共识 / microdescriptor `a` 行是附加 OR 地址，不是 `sha256=` digest
- C Tor / Arti：双栈目标同时带 IPv4 与 IPv6 specifier

## 实现（100% 纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/directory/oraddress.go` | 解析 `a [ipv6]:port`；`AdvertisesExtendIPv6` / `ShouldIncludeExtendIPv6` |
| `pkg/directory/directory.go` | 共识 `a` 行写入 `Relay.IPv6` / `IPv6Port` |
| `pkg/directory/microdesc.go` | 旧 microdesc 仍可能带 `a` 行时回填 |
| `pkg/circuit/extension.go` | `buildExtend2Data` 在身份 specifier 之后追加 `[01]` |

## 字节布局

```
NSPEC = 4
[00] LSLEN=6  IPv4(4) || PORT(2 BE)
[02] LSLEN=20 RSA SHA-1
[03] LSLEN=32 Ed25519
[01] LSLEN=18 IPv6(16) || PORT(2 BE)
HTYPE HLEN HDATA
```

IPv4-only：NSPEC=3，无 `[01]`。

## 禁止

- 对未宣告 IPv6 ORPort 的节点硬塞 `[01]`。
- 把 `Relay=4` 当成已支持 IPv6 EXTEND。
- 用 C 库 / `import "C"` / CGO。
- 无真实双栈 EXTENDED2 就把状态标成 WORKING。

## 真实网络

`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration -run TestRealExtend2IPv6`

未跑通前本项为 UNVERIFIED。
