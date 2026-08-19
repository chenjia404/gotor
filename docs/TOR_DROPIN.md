# gotor 与 Tor 二进制 / torrc 兼容说明

**产物**：单一二进制 `bin/gotor`（`make build`）。

**范围**：客户端 + 洋葱服务托管 + ORPort 中继（含出口）。未知 torrc 键**静默忽略**。
**明确不做**：PT 生产路径（obfs4/Bridge 真连）、TransPort/NATDPort、完整 Windows NT service、Directory Authority。

## CLI（对齐 C Tor 0.4.9.x）

```bash
gotor -f /etc/tor/torrc
gotor --torrc-file /etc/tor/torrc
gotor -f - < torrc
gotor --defaults-torrc defaults --config torrc
gotor --allow-missing-torrc -f /missing
gotor SocksPort 9150 ControlPort 9151
gotor --hash-password 'secret'    # 输出 16:...
gotor --verify-config
gotor --dump-config short|full
gotor --list-torrc-options
gotor --list-deprecated-options
gotor --list-modules
gotor --list-fingerprint [rsa|ed25519]  # 需已有 DataDirectory/keys，不自动生成
gotor --keygen
gotor --version                   # Tor version 0.4.9.11 (gotor).
```

`--quiet` / `--hush` 降低日志。`--dbg-*` 忽略。`--service` / `--nt-service` 明确报未实现后退出。

无 `-f` 时依次尝试：**`/etc/tor/torrc`**、**`$HOME/.torrc`**，然后 `./torrc`（额外便利，不覆盖 C Tor 顺序）。未指定 `--defaults-torrc` 时若存在则加载 `/etc/tor/torrc-defaults`。

`--verify-config` / `--dump-config` / `--list-fingerprint` / `--keygen` **不启动网络**。
`--list-fingerprint` 在 `DataDirectory/keys` 无身份钥时**报错退出**（不静默写钥；生成请用 `--keygen`）。
`--allow-missing-torrc` **仅**在文件不存在时忽略；权限/解析失败仍退出。

### 库 API 与二进制默认不同

`DefaultConfig()`（库）行为不变：自动选空闲端口、`~/.config/go-tor`。
`ParseCLI` 使用 `DefaultCLIConfig()`：SocksPort=9050、**ControlPort=0（默认不开放控制口，对齐 C Tor 0.4.9）**、DataDirectory=`~/.tor`（Windows: `%APPDATA%\tor`）、CacheDirectory 默认等于 DataDirectory。

要开控制口请显式写 `ControlPort 9051`（或 `ControlSocket`）。只要控制口会监听，gotor 会**默认启用 CookieAuthentication** 并写入 `DataDirectory/control_auth_cookie`（0600）；可与 `HashedControlPassword` 并存。CLI 路径**不接受**无认证的空 `AUTHENTICATE`。

## 已识别并尽量生效的 torrc 键

| 键 | 行为 |
|----|------|
| SocksPort [addr:]port \| auto \| 0 \| unix:/path [Isolate*] | 0=关闭；auto=选空闲端口；unix socket 启动前删除陈旧文件，listen 后 `chmod 0600`（仅 `UnixSocksGroupWritable 1` 时 0660） |
| ControlPort / ControlSocket | **默认 0 不监听**；显式开启后默认 CookieAuthentication + `control_auth_cookie` 0600；unix socket `chmod 0600` |
| DataDirectory / CacheDirectory | 状态与目录缓存 |
| PidFile | 启动写、停止删 |
| RunAsDaemon | Unix re-exec；Windows 警告 |
| ClientOnly | 与 ExitRelay/ORPort 冲突则拒绝 |
| DisableNetwork | 起监听，不拉共识/不建路 |
| HTTPTunnelPort | HTTP CONNECT，经电路转发；复用 SafeSocks/RejectInternal/MapAddress；非回环绑定告警 |
| DNSPort | UDP DNS，经 RELAY_RESOLVE，禁止本机 DNS；非回环绑定告警 |
| CookieAuthentication / CookieAuthFile | `control_auth_cookie` 0600 |
| HashedControlPassword | RFC2440 S2K |
| ClientUseIPv4 / ClientUseIPv6 / ClientPreferIPv6ORPort | 解析入库 |
| MapAddress / AutomapHosts* / VirtualAddrNetwork* | 解析；MapAddress 接到 SOCKS 与 HTTPTunnel（主机名大小写不敏感） |
| ClientOnionAuthDir | 加载 `*.auth_private` |
| SafeSocks / TestSocks / ClientRejectInternalAddresses | SOCKS 与 HTTPTunnel 拒绝 IP 字面量 / 记录 / 拒绝内网 |
| CircuitPadding / ReducedCircuitPadding / ConnectionPadding | 解析并接到已有 padding 开关 |
| SocksTimeout / FallbackDir / UseDefaultFallbackDirs / AvoidDiskWrites | 解析；FallbackDir 接到目录权威列表 |
| Log / LogLevel | 级别与可选 file |
| UseBridges / Bridge / ClientTransportPlugin | **仅解析**，无 PT 生产路径 |
| ExitNodes / EntryNodes / Exclude* / StrictNodes | 解析入库（选路接线持续完善） |
| HiddenServiceDir / Port / Version / MaxStreams | 启动托管洋葱服务 |
| ORPort / Nickname / ContactInfo / Address | 中继身份与宣告地址；`ORPort` 必须 >0 才能当中继 |
| ExitRelay / ExitPolicy / ReduceExitPolicy / IPv6Exit | **ExitRelay 1 启用出口**；策略顺序匹配，无匹配默认 accept（C Tor）；`DefaultCLIConfig()` 默认 ExitRelay=0 |
| ExitPolicyRejectPrivate | 默认 1：拒绝 RFC1918/环回/链路本地/CGN/文档网段等 |
| ExitPolicyRejectLocalInterfaces | 默认 1：拒绝本机网卡地址 |
| DirPort / DirCache | 解析；DirCache 尽量用 CacheDirectory 落盘文件应答 BEGIN_DIR / 明文 DirPort |
| MyFamily / FamilyID | 解析；MyFamily 写入描述符 `family` 行 |
| RelayBandwidthRate/Burst、BandwidthRate/Burst | 接到出口数据面令牌桶 |
| TransPort / NATDPort | 非 0 拒绝启动（未实现） |
| %include / Include | 递归包含；通配符词法排序；目录忽略点文件 |
| 引号值 | `DataDirectory "/path with spaces"` |

## DataDirectory（C Tor 同名）

- `lock`（flock；占用则退出）
- `state`（含 `Guard in=default rsa_id=... nickname=...`；读优先于 `guard_state.json`，写两者；`rsa_id` 须为 40 位十六进制，否则丢弃并回退 json）
- `control_auth_cookie`
- `keys/`（`--keygen` / `--list-fingerprint`；可读 C Tor `secret_id_key` / `ed25519_master_id_secret_key` / `secret_onion_key_ntor`）
- HiddenServiceDir（既有）
- CacheDirectory：`cached-certs`（DataDirectory，既有）、`cached-microdesc-consensus`（验签成功后原子写；启动再验签，过期不用）、`cached-microdescs` + `cached-microdescs.new`（`@last-listed`；哈希前去掉 `@` 行）

## 中继 / 出口（PARTIAL）

`ORPort > 0` 启用中继。`ExitRelay 1` 且 `ORPort > 0` 时作为出口：执行 ExitPolicy、处理 RELAY_BEGIN/DATA/END/RESOLVE，描述符写入真实 accept/reject。`ExitRelay 1` 且 `ORPort==0` 拒绝启动。策略最终等价 `reject *:*` 时仍启动，但不会放行常见端口（权威不会给 Exit flag）。

`DefaultCLIConfig()` **默认不打开** ExitRelay。未经验证的真网权威收录不得宣称 WORKING。
