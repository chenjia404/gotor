# gotor 中继与出口

## 非出口

```bash
gotor ORPort 9001 Nickname gotorMiddle ExitRelay 0
```

## 出口

```bash
gotor -f examples/torrc.exit.sample
# 或
gotor ORPort 9001 ExitRelay 1 ReduceExitPolicy 1 SocksPort 0 \
  ExitPolicy 'accept *:80' ExitPolicy 'accept *:443' ExitPolicy 'reject *:*'
```

### 出口 torrc 键

- `ExitRelay`、`ExitPolicy`、`ExitPolicyRejectPrivate`（默认 1）、`ExitPolicyRejectLocalInterfaces`（默认 1）
- `ReduceExitPolicy`、`IPv6Exit`
- `ORPort`（必须 >0）、`Nickname`、`ContactInfo`、`Address`
- `DirPort` / `DirCache`、`MyFamily` / `FamilyID`
- `RelayBandwidthRate` / `RelayBandwidthBurst`（及 `BandwidthRate` / `Burst`）
- `PublishServerDescriptor`、`AssumeReachable`
- `SocksPort 0`（出口中继常见，已支持关闭 SOCKS）

无 `ExitPort` 键；出口端口由 ExitPolicy 决定。

### 行为（PARTIAL）

- 电路末端解密 RELAY（Tor1 AES-CTR + digest）；ntor-v3 回 `sendme_inc=31`
- `RELAY_BEGIN`：解析地址/端口/flags → ExitPolicy（含私网/本机接口）→ 只拨允许的 IP → `RELAY_CONNECTED` → 双向 `DATA` / `END` / `SENDME`
- `RELAY_RESOLVE` / `RESOLVED`：出口做 DNS（getaddrinfo 是出口合法行为）；过滤私网/特殊用途地址；`.onion` 拒绝；StreamID=0 丢弃
- `RELAY_BEGIN_DIR`：有 DirCache 时接 CacheDirectory 落盘文件，否则 `NOTDIRECTORY`
- 无匹配规则时默认 accept（C Tor）；`ExitPolicyRejectPrivate 1` 前置拒绝私网
- `ReduceExitPolicy 1` 追加 C Tor 精简端口表；未写绝对 `accept *:*` / `reject *:*` 时追加默认或精简策略
- server descriptor 写入真实 `accept`/`reject` 与 `ipv6-policy`；**不**自己宣告 Exit/BadExit
- 可读 C Tor `DataDirectory/keys` 身份文件，避免换二进制丢身份
- 默认 `go test` 不访问公网；出口解析仅在运行时发生

### 启动校验

- `ExitRelay 1` 且 `ORPort==0` → 错误
- `ExitRelay 1` 且策略不会放行 80/443/6667 → 警告（权威不会给 Exit flag）
- `DefaultCLIConfig()` 默认 `ExitRelay 0`

## 未完成 / 已知限制

- 真网权威落库与 Exit flag 收录：**未验证**，不标 WORKING
- PT / Bridge / ExtORPort / ServerTransportPlugin 生产路径：明确不做
- Directory Authority：不做
- DirPort / BEGIN_DIR 可服务已缓存的 `cached-microdesc-consensus` / `cached-microdescs` / `cached-certs`（`/tor/keys/fp`、`/tor/keys/all`）、最多 72 小时历史→当前 limited-ed、gzip/deflate/`.z`、If-Modified-Since 304、FPRLIST 签名过滤（未过半 404）与 x-zstd / x-tor-lzma（共识/diff 缓存 lzma）；仍缺 ns/microdesc 分库、预压缩 diff 库与真网被当缓存，未宣告 DirCache=2
- 末端跳可受理 ESTABLISH、INTRODUCE1→INTRODUCE2、RENDEZVOUS1 会合与 HSDir `/tor/hs/3` 验签收/服；仍缺限速/生命周期/哈希环与真网被选，未宣告 HS*
- 入站可校验 AUTHENTICATE type 3（LinkAuth=3）；普通客户端不认证。无 AuthType 1。
- ntor-v3 客户端请求 type 3 `[02 06]` 时走 CGO（AES-128 UIV+ / v1）；未请求则仍 tor1。描述符不写 `Relay=5-6`。
- extra-info：描述符写 `extra-info-digest`，与 extra-info 一次 POST；只写已完成 900s 观测格。无观测不写 history。仍缺 dirreq/exit/conn-bi-direct 与真网归档。
- 官方 `DoS*`：默认 auto 关闭。显式 1 时每 IP 并发 OR 上限 + CREATE2 令牌桶；`DoSRefuseSingleHopClient` 仅在成功 EXTEND 后放行 BEGIN。不改 `ConnLimit`。仍缺共识参数与连接速率桶。见 `docs/interop/dos-relay.md`。
- FlowCtrl=2 出口侧使用 `sendme_inc=31` 与初始 cwnd=124，未实现完整 Vegas 自适应
- 客户端 SOCKS 流量不会被当成出口
