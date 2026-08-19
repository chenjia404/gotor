# DNS / RELAY_RESOLVE 互操作

**日期**：2026-08-19

对照：

- Spec：https://spec.torproject.org/tor-spec/remote-hostname-lookup.html
- Spec：https://spec.torproject.org/tor-spec/relay-cells.html
- C Tor：`src/core/or/relay.c`（`RELAY_COMMAND_RESOLVE` + `stream_id==0` 直接丢弃，bug 7889）
- C Tor：`src/core/or/connection_edge.c`（RESOLVED 多条 answer）

## 曾经 BROKEN

1. **StreamID=0**：把 RESOLVE 当成 control cell。真实 exit 丢掉，查询永不完成。
2. **PTR 发 TYPE|LENGTH|ADDRESS 二进制**：spec 要求与正向相同的 NUL 结尾主机名（`in-addr.arpa` / `ip6.arpa`）。
3. **只取第一条应答**；把 0xF0/0xF1 的 Value 当成 1 字节 RCODE。C Tor 写入的是字符串 `"Error resolving hostname"`。

## 现在

- 电路分配**非 0** StreamID；SOCKS `RELAY_BEGIN` 与 `RELAY_RESOLVE` 共用 `Circuit.AllocateStreamID`。
- 正向：`hostname\0`
- 反向：`1.2.0.192.in-addr.arpa\0` / nibble 反序 `ip6.arpa\0`
- 收齐全部 IPv4（在前）+ IPv6；有地址时忽略错误记录。
- `.onion` 拒绝走 exit DNS。
- 生产路径禁止 `net.Lookup*`（静态扫描）。

## 真实网络

`TestRealRelayResolve`：3-hop 上解析 `www.torproject.org` 得到 IP；同时把 `net.DefaultResolver` 指到不可达地址。
