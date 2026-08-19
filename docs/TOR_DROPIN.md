# gotor 与 Tor 二进制 / torrc 兼容说明

**产物**：单一二进制 `bin/gotor`（`make build`）。

**范围**：客户端 + 洋葱服务托管。中继后续再做。未知 torrc 键**静默忽略**。

## CLI（对齐 C Tor 习惯）

```bash
gotor -f /etc/tor/torrc
gotor --defaults-torrc defaults --config torrc
gotor SocksPort 9150 ControlPort 9151
gotor --hash-password 'secret'    # 输出 16:...
gotor --list-torrc-options
gotor --version
```

亦接受遗留：`-config`、`-socks-port`、`-control-port`、`-data-dir`、`-log-level`。

无 `-f` 时依次尝试：`./torrc`、`~/.torrc`、`/etc/tor/torrc`；皆无则零配置。

## 已识别并生效的 torrc 键（摘录）

| 键 | 行为 |
|----|------|
| SocksPort [addr:]port [Isolate*] | 监听地址/端口与隔离 flag |
| ControlPort | 控制口 |
| DataDirectory | 数据目录 |
| CookieAuthentication / CookieAuthFile | 写 `control_auth_cookie`，PROTOCOLINFO 宣告 COOKIE |
| HashedControlPassword | RFC2440 S2K（`16:`），AUTHENTICATE 明文校验 |
| Log / LogLevel | 级别与可选 file |
| UseBridges / Bridge / ClientTransportPlugin | 桥梁与 PT |
| ExitNodes / EntryNodes / Exclude* / StrictNodes | 解析入库（选路接线持续完善） |
| HiddenServiceDir / Port / Version / MaxStreams | 启动托管洋葱服务 |
| %include / Include | 递归包含（深度上限 16） |

其余键静默忽略。

## DataDirectory

- `control_auth_cookie`（CookieAuthentication 时）
- `cached-certs`（既有）
- HiddenServiceDir 下密钥与状态（既有 persistence）

## 洋葱服务托管（PARTIAL）

- torrc：`HiddenServiceDir` / `HiddenServicePort` 启动托管
- ESTABLISH_INTRO：按 rend-spec（Ed25519 AUTH_KEY、HANDSHAKE_AUTH、签名）
- 描述符上传：仅 BEGIN_DIR（禁止明文 DirPort）
- 引言点：优先 Fast+Stable 中继

真网发布/客户端接入完整验收仍在推进。
