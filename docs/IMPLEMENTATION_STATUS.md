# gotor 实现状态（按当前代码重审）

**日期**：2026-08-19  
**分支**：`cursor/dns-resolve-leak-0ece`  
**原则**：UNVERIFIED 不能算完成。文档（ROADMAP.md ~98%、AUDIT.md、GAPS.md）不可盲信，必须以仓库代码 + Tor Spec / C Tor / Arti 为准。

状态定义：

| 状态 | 含义 |
|------|------|
| WORKING | 符合 spec、有单测、且经过真实 Tor Network 验证 |
| PARTIAL | 有实现，但缺关键步骤、校验或真实网络证明 |
| BROKEN | 实现存在且会误导调用方，或协议错误到无法互操作 |
| MISSING | 无可用实现 |
| UNVERIFIED | 代码存在，但尚未用真实 Tor Network / 官方向量证明 |

---

## 总览（Client 主链路）

第一轮目标是真实 3-hop + SOCKS5 + `check.torproject.org` `IsTor=true`。在该 E2E 通过之前，**Tor Client basic interoperability 不得标 WORKING**。

| 组件 | 状态 | 说明 |
|------|------|------|
| Directory / Consensus | PARTIAL | 生产验签已在真实网络通过（9/9 权威，10143 relays）。长期 fixture 与证书落盘仍弱 |
| Microdescriptor fetch/parse | PARTIAL | 解析与 digest 已按 spec 修正，真实网络可填充密钥；缺长期 fixture 回归 |
| Relay.IdentityKey / NtorOnionKey | PARTIAL | 现来自 microdescriptor，禁止全零 fallback；须由 fetch 成功才可用 |
| Link TLS | PARTIAL | TLS 能连上；身份不以 TLS 成功为准 |
| VERSIONS / CERTS / AUTH_CHALLENGE / NETINFO | WORKING | VERSIONS CircID=2、CERTS type4 验签、NETINFO 已在真实 Guard 握手通过；AUTH_CHALLENGE 客户端路径按 spec 跳过 |
| CREATE2 / ntor / CREATED2 | WORKING | 真实 Guard CREATE2/CREATED2 已成功（72 字节密钥） |
| EXTEND2 / EXTENDED2 | WORKING | 真实 Guard→Middle / Middle→Exit EXTEND2 已成功 |
| Circuit crypto / digest | WORKING | 真实 RELAY_DROP / EXTEND2 / BEGIN / DATA 已证明 AES-CTR + SHA-1 digest 与 Guard 一致；仍缺官方 cell 向量 |
| RELAY_BEGIN/CONNECTED/DATA/END | WORKING | 真实 exit 流已拉取 check.torproject.org |
| SENDME / flow control | WORKING | 电路级 SENDME v1 已在真实网络 256KB+ soak 通过；流级仍为空（spec）；FlowCtrl=2 未做 |
| SOCKS5 | WORKING | SOCKS5 + `https://check.torproject.org/api/ip` 已返回 `IsTor=true` |
| DNS / RELAY_RESOLVE | WORKING | 真实 3-hop RESOLVE `www.torproject.org` 得 IPv4+IPv6；本机 resolver 不可达仍成功 |
| Guard / Path selection | PARTIAL | 选路存在，不在缺 key 时静默成功 |
| Exit policy | PARTIAL | 已解析共识/microdesc `p` 行并按端口过滤；预建电路改选 443；完整策略与 IPv6 `p6` 未做 |
| Onion Service v3 | BROKEN / MISSING | 本轮不实现；hs-ntor 未做；旧代码误用 circuit ntor |
| Relay / Bridge | BROKEN / UNVERIFIED | 本轮不优先；服务端 ntor 仍可能用错 NODEID |
| Control Protocol | PARTIAL | 框架存在，非本轮验收 |
| Pluggable Transport | PARTIAL | 框架，非本轮验收 |

---

## 分类明细

### Directory / Consensus — PARTIAL

- 默认拉 `consensus-microdesc`（当前 Tor Network 默认格式）。
- `r` 行 identity 按 **无 padding base64** 解成 20 字节 `RSAIdentity`，并提供 40 字符大写 hex 给 CERTS。
- `valid-after` / `fresh-until` / `valid-until`、flags、bandwidth、`m` digest 有解析。
- Authority 列表已更新到当前公开 IP。
- 生产 `FetchConsensus` 在 metadata 之外强制 `VerifyConsensusSignatures`：`/tor/keys/fp/<id>`、`dir-signing-key`、`dir-key-certification`、`dir-key-crosscert`、majority（5/9）。
- 真实网络：`TestRealConsensusSignatures` 验证 **9/9** 权威签名，共识含 10143 个 relay。
- 详见 `docs/interop/consensus.md`。
- **缺口**：证书未落盘；缺官方长期 fixture。`docs/MICRODESCRIPTOR_FETCHING.md` 仍写错 `a sha256=` 行（实际是 `m` 行）。

### Microdescriptor — PARTIAL（本轮已修解析 blocker）

**曾经 BROKEN：**

1. `id ed25519` 被读成下一行（spec 是同一行 `id ed25519 <base64>`）。
2. digest 用带 padding 的 StdEncoding，无法匹配共识 `m` 行 raw base64。
3. 串行拉取 + 过短 HTTP timeout。

**现在：** `pkg/directory/microdesc.go` 并行拉取、正确 digest、同 extra 行解析 ntor / ed25519 / family / policy。缺 key **报错**，不用 `make([]byte,32)`。

详见 `docs/interop/microdescriptor.md`。

### Relay.IdentityKey / NtorOnionKey — PARTIAL

- `NtorOnionKey`：microdescriptor `ntor-onion-key`。
- `IdentityKey`：microdescriptor `id ed25519`（32 字节，给 EXTEND2 `[03]`）。
- `RSAIdentity`：共识 `r` 行（20 字节，ntor NODEID + EXTEND2 `[02]`）。
- `HasNtorKeys()` / `HasExtendKeys()` 拒绝全零。

### Link VERSIONS CircID 宽度 — 本轮已修（原 BROKEN）

TLS 能连上但 `timeout waiting for VERSIONS`：VERSIONS 被编成 4 字节 CircID，对端当成 PADDING。现已按 `CIRCID_LEN(0)=2` 发送/接收，协商后再切 4 字节。见 `docs/interop/link-versions.md`。

### Link protocol / TLS — PARTIAL

- 生产 `connectToRelay` 在 TLS 之后调用 `protocol.PerformHandshake`。
- 顺序：VERSIONS → CERTS →（跳过 AUTH_CHALLENGE/PADDING）→ NETINFO。
- **不能**把 TLS 成功当成 identity 验证成功。CERTS 校验在 `pkg/protocol`。
- `InsecureSkipVerify` 仍可能出现在 TLS 配置（Tor 用自签名 + CERTS）。须靠 CERTS/fingerprint，而不是关闭校验后宣称已验证。
- 真实握手测试：`integration/link_test.go`（`TOR_INTEGRATION_TEST=1`）。

### ntor / CREATE2 / EXTEND2 — WORKING（经典 ntor `0x0002`）

**曾经 BROKEN（无法与 C Tor / Arti 互操作）：**

- NODEID 用 Ed25519 前 20 字节。
- `AUTH = HKDF(secret_input)` 而不是 `HMAC(auth_input, t_mac)`。
- 密钥直接 `HKDF(secret_input)` 而不是 `HKDF-Expand(KEY_SEED)`。
- 缺 key 时 `make([]byte, 32)` fallback。
- CircID 从 1 起，未置 MSB（link proto ≥4 发起方必须 MSB=1）。
- EXTEND2 未带 `[02]` RSA / `[03]` Ed25519 specifier。
- `SendRelayCell` 要求 `StateOpen`，build 期间是 `StateBuilding`。
- 无连接级 cell mux，EXTENDED2 到不了等待者。
- builder 在 CREATE2 前预加空 hop。

**现在对照：**

- Spec：https://spec.torproject.org/tor-spec/create-created-cells.html
- C Tor：`src/core/crypto/onion_ntor.c`
- Arti：`crates/tor-proto/src/crypto/handshake/ntor.rs`

实现见 `pkg/crypto/ntor.go`、`docs/interop/ntor.md`。

**本轮已用真实网络验证：** Guard CREATE2、Middle/Exit EXTEND2、3-hop READY、SOCKS5 `IsTor=true`。ntor-v3 未实现（经典 ntor `0x0002` 仍被 relay 接受）。

### Circuit crypto / Relay cell — WORKING（主路径）

- 加解密顺序：发送先 Exit 再 Middle 再 Guard；接收反向逐层 decrypt。有本地 roundtrip 测试。
- digest / recognized / stream ID / length 有实现。
- 真实 RELAY_DROP 不再触发 DESTROY；EXTEND2 / BEGIN / DATA 已跑通。
- **缺口**：缺官方 C Tor/Arti relay-cell 向量；cell tracer（`pkg/debug`，`GOTOR_CELL_TRACE=1`）默认关闭且不记用户 payload。

### SENDME / Flow control — WORKING（电路级 v1）

- circuit window 1000 / +100；stream window 500 / +50。
- 电路级 SENDME 发 version 1，DIGEST=触发 cell 的完整 20 字节滚动 SHA-1。
- 发出 DATA 时在 `package_window % 100 == 0` 入队；收到 SENDME 必须 FIFO 匹配，否则拆路。
- 流级 SENDME 仍为空（spec）。
- DATA padding 随机化。
- 真实网络：`TestRealFlowControlSoak` 经 SOCKS 下载 282KB，电路未 DESTROY。
- **缺口**：1MB–100MB soak、FlowCtrl=2（ntor-v3 congestion control）。

### SOCKS5 / DNS — WORKING（CONNECT） / PARTIAL（RESOLVE）

- SOCKS5 CONNECT：域名 / IPv4 / IPv6。
- 域名走 Exit 解析（`socks5h` / RELAY_BEGIN hostname）。
- 真实 `https://check.torproject.org/api/ip` 已返回 `IsTor=true`。
- RELAY_RESOLVE：非 0 StreamID、arpa PTR、收集多条应答；0xF0/0xF1 Value 按字符串处理。
- CONNECT 仍把 hostname 原样放进 RELAY_BEGIN（socks5h），不走本机 DNS。
- 生产路径静态禁止 `net.Lookup*`。
- 真实网络：`TestRealRelayResolve` 经 exit `artikel5ev8b` 解析 `www.torproject.org` → `204.8.99.144` + IPv6；PTR → `web-dal-07.torproject.org`；`.invalid` 回 `0xF1 Error resolving hostname`。本机 `DefaultResolver` 被指到不可达地址。
- 详见 `docs/interop/dns.md`。

### Guard / Path / Exit policy — PARTIAL

- Guard 管理与带宽加权选路存在。
- 选路不保证已有 microdesc key；client 在 build 前 `FetchMicrodescriptorsFor`，缺 key 则失败。
- 预建电路按端口 443 选 exit；`p` 行摘要允许则过滤，禁止再把非 Exit 当 fallback。

### Onion Service — BROKEN / MISSING（本轮不做）

- 地址解析等骨架存在。
- hs-ntor、经 circuit 的 HSDir、完整 INTRODUCE/RENDEZVOUS 未达到互操作。
- `BuildRendezvous1Cell` 曾用 circuit ntor + 32 字节 Ed25519，与 spec 不符。

### Relay / Bridge — BROKEN / UNVERIFIED（本轮不做）

- OR listener / descriptor 骨架存在。
- `pkg/relay/circuit_handler.go` 仍可能把 Ed25519 public 当 ntor NODEID。

---

## 本轮已修的最高优先级 blocker

| # | Blocker | Root cause | Spec / 参考 |
|---|---------|------------|-------------|
| 1 | ntor 无法与 mainnet 握手 | H 误实现为 HKDF；NODEID 用错 | tor-spec create-created-cells；C Tor `onion_ntor.c`；Arti `ntor.rs` |
| 2 | microdesc 密钥匹配失败 | digest padding；`id ed25519` 换行解析 | dir-spec microdescriptor |
| 3 | zero-key fallback | 缺 key 仍 `make([]byte,32)` | 禁止静默 fallback |
| 4 | 生产路径无 link handshake | 只做 TLS | tor-spec negotiating-channels |
| 5 | EXTENDED2 无人投递 | 无 mux | 连接上多 circuit cell 分发 |
| 6 | Building 不能发 RELAY | `SendRelayCell` 只允许 Open | EXTEND2 必须在 build 期间发送 |
| 7 | CircID 被拒 | MSB 未置 1 | link proto ≥4 |
| 8 | EXTEND2 缺 identity specifier | 只发 IPv4 | `[00][02][03]` |
| 9 | VERSIONS 超时 | CircID 用 4 字节，对端当成 PADDING | negotiating-channels CIRCID_LEN(v=0)=2 |
| 10 | CERTS type 4 验签失败 | ExtLen 被当成含 type+flags；identity 误用 signing key | cert-spec；Arti `tor-cert` encode.rs |
| 11 | EXTEND2 超时 | RELAY cell `Length` 未设，Encode 写出 0，Guard 无法解析 EXTEND2 | tor-spec relay-cells |
| 12 | EXTEND2 DESTROY reason=1 | ntor 电路密钥对 KEY_SEED 二次 HKDF-Extract；AUTH 仍过，AES/digest 与 Guard 不一致 | C Tor onion_ntor.c IKM=secret_input；setting-circuit-keys |
| 13 | 预建电路假就绪 | `buildInitialCircuits` sleep 1s 后宣称已建好；pool 要等 30s ticker 才动手 | Start 与 WaitUntilReady 分离；pool 立即 prebuild |
| 14 | HTTPS 选到只放行 80 的 exit | `SelectPath(80)` 且只看 Exit flag | 预建用 443；解析 `p` 行摘要 |
| 15 | 大流量 DESTROY / hang | 电路级 SENDME 发空 v0，现代 exit 拒收 | flow-control SENDME v1；C Tor sendme.c；Arti SendmeValidator |
| 16 | 共识只数签名个数 | `VerifyConsensusSignatures` 从未被 `FetchConsensus` 调用；证书取第一把 RSA（identity） | dir-spec consensus-formats / authority-key-certificates；C Tor signed boundaries |
| 17 | RELAY_RESOLVE 被 exit 丢掉 | StreamID=0（C Tor bug 7889）；PTR 发二进制而非 arpa 名 | remote-hostname-lookup；relay-cells |

---

## 测试

| 测试 | 作用 | 默认 `go test ./...` |
|------|------|----------------------|
| `pkg/crypto` ntor 单测 / 正确性 | HMAC + 20-byte NODEID | 运行 |
| `pkg/directory` microdesc 单测 | 同行 identity、raw digest | 运行 |
| `pkg/directory` 共识验签单测 | 自生成 RSA 证书 + 迷你共识；篡改必失败 | 运行 |
| `integration/link_test.go` | 真实 TLS+handshake | 需 `-tags=integration` + `TOR_INTEGRATION_TEST=1` |
| `integration/e2e_real_tor_test.go` | 共识验签 / CREATE2 / 3-hop / IsTor / SENDME soak / RELAY_RESOLVE | 同上 |
| `scripts/test-real-tor.sh` | 启动 client + socks5h curl | 手动 |

`testdata/ctor-vectors/crypto/ntor_handshake.json` 与 `testdata/arti-vectors/...` 已按**正确算法重生**，目前不是从 C Tor/Arti 仓库原样导出。不得据此宣称已有官方 cross-impl 向量。

---

## 文档债务

- `ROADMAP.md` 声称 ~98% 完成、Onion/Bridge 已完成：**过期且不实**。
- `GAPS.md` 部分条目（ntor placeholder、VerifyDigest）已被 AUDIT 标为过期，但 AUDIT 未发现 ntor 算法本身错误。
- `docs/NTOR_HANDSHAKE.md` 正文仍有错误公式；文首已加警告。
- `docs/MICRODESCRIPTOR_FETCHING.md` 的 `a` 行描述过期。

---

## 第一轮完成标准（已达到：经典 ntor / AES-CTR-SHA1）

只有同时满足以下全部条件，才能把 **Tor Client basic interoperability** 标为 WORKING：

1. 真实 Guard CREATE2 成功  
2. Guard → Middle EXTEND2 成功  
3. Guard → Middle → Exit circuit READY  
4. SOCKS5 → `https://check.torproject.org/api/ip` 返回 `IsTor == true` 且 IP ≠ 本机公网 IP  
5. 默认 `go test ./...` 不因公网失败  
6. `TOR_INTEGRATION_TEST=1 go test ./integration/... -tags=integration` 通过  

当前：`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration` 已通过 CREATE2、EXTEND2、3-hop、`IsTor=true`、SENDME v1 soak（≥256KB）、RELAY_RESOLVE（本机 DNS 不可达）。  
**Tor Client basic interoperability 可标 WORKING（经典 ntor / AES-CTR-SHA1 / SENDME v1 / RELAY_RESOLVE）**。ntor-v3、FlowCtrl=2、更大流量 soak 仍未做。
