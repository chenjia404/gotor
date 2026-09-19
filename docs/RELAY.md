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
- FlowCtrl=2 出口用 TOR_VEGAS：额度 `cwnd-inflight`，共识 `cc_*` 注入；orconn_blocked 采自向客户端写出排队/慢写；经典电路仍 `+100`
- `RELAY_BEGIN`：解析地址/端口/flags → ExitPolicy（含私网/本机接口）→ 只拨允许的 IP → `RELAY_CONNECTED` → 双向 `DATA` / `END` / `SENDME`
- `RELAY_RESOLVE` / `RESOLVED`：出口做 DNS（getaddrinfo 是出口合法行为）；过滤私网/特殊用途地址；`.onion` 拒绝；StreamID=0 丢弃
- `RELAY_BEGIN_DIR`：有 DirCache 时接 CacheDirectory 落盘文件，否则 `NOTDIRECTORY`
- 无匹配规则时默认 accept（C Tor）；`ExitPolicyRejectPrivate 1` 前置拒绝私网
- `ReduceExitPolicy 1` 追加 C Tor 精简端口表；未写绝对 `accept *:*` / `reject *:*` 时追加默认或精简策略
- server descriptor 写入真实 `accept`/`reject` 与 `ipv6-policy`；**不**自己宣告 Exit/BadExit
- 描述符 `proto` 只宣告已实现：`Cons=2 Desc=2 FlowCtrl=1-2 Link=3-5 LinkAuth=3 Microdesc=2 Relay=2-4`。不写 `Circuit=`、中继侧未实现的 Padding/Conflux、DirCache=2 / HS* / Relay=5-6
- 描述符 `platform` 与 GETINFO `version` 为 `Tor 0.4.9.11 (gotor)`（CLI `--version` 同源）
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
- DirPort / BEGIN_DIR 可服务已缓存的 `cached-microdesc-consensus` / `cached-consensus` / `cached-microdescs` / `cached-certs`（`/tor/keys/fp`、`/tor/keys/all`）、最多 72 小时历史→当前 limited-ed、gzip/deflate/`.z`、If-Modified-Since 304、FPRLIST 签名过滤（未过半 404）、x-zstd / x-tor-lzma 与预压缩 consdiff 库；仍缺真网被当缓存，未宣告 DirCache=2
- 末端跳可受理 ESTABLISH、INTRODUCE1→INTRODUCE2、RENDEZVOUS1 会合与 HSDir `/tor/hs/3` 验签收/服；DirCache 在共识哈希环就绪后按 spread_store 拒绝非责任 POST。引言点按 ESTABLISH_INTRO `DOS_PARAMS` 或共识 `HiddenServiceEnableIntroDoS*` 做 INTRODUCE2 令牌桶。会合点仅末跳、未会合 cookie 10 分钟 TTL。仍缺 extra-info `hidserv-*` 与真网被选，未宣告 HS*
- 入站可校验 AUTHENTICATE type 3（LinkAuth=3）；普通客户端不认证。无 AuthType 1。
- ntor-v3 客户端请求 type 3 `[02 06]` 时走 CGO（AES-128 UIV+ / v1）；未请求则仍 tor1。描述符不写 `Relay=5-6`。出口电路级 SENDME v1 带 20 字节 digest 或 16 字节 CGO tag，并 FIFO 校验客户端 SENDME。FlowCtrl=2 出口用 TOR_VEGAS（`cwnd-inflight`），共识 `cc_*` 注入；orconn_blocked 采自向客户端写出排队/慢写。
- extra-info：描述符写 `extra-info-digest`，与 extra-info 一次 POST；只写已完成 900s 观测格。入站 OR 与出站中间跳 OR 套接字计入 read/write-history。`conn-bi-direct` / `ipv6-conn-bi-direct` 满 24h 且有分类才写（后者仅 IPv6）。`dirreq-v3-resp` 满 24h 且有 v3 网络状态应答才写。`dirreq-v3-ips` / `reqs` 无 geoip 只写 `??=N`（向上取 8）。`dirreq-v3-direct-dl` / `tunneled-dl` 满 24h 且该通道有 HTTP 200 才写 `complete`（DirPort vs BEGIN_DIR；无分位数）。无观测不写 history / 双向行 / dirreq。仍缺真实国家码、exit/hidserv 与真网归档。
- 官方 `DoS*`：默认 auto 关闭；auto 跟共识 `DoSCircuitCreationEnabled` / `DoSConnectionEnabled` / `DoSStreamCreationEnabled`。显式 1 时每 IP 并发 OR 上限 + CREATE2 令牌桶 + 连接速率桶（20/40/24h）+ 每电路流创建桶（100/300，缺省拒绝流）。`DoSCircuitCreationDefenseType` 1=无动作、2=拒绝（缺省）。`DoSRefuseSingleHopClient` 对未 EXTEND 的普通客户端 DESTROY；已 AUTHENTICATE 且共识 nodelist 收录的中继单跳放行。不改 `ConnLimit`。见 `docs/interop/dos-relay.md`。
- 客户端 SOCKS 流量不会被当成出口
