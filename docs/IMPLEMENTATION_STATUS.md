# gotor 实现状态（按当前代码重审）

**日期**：2026-08-18  
**分支**：`cursor/real-tor-interop-0ece`  
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
| Directory / Consensus | PARTIAL | 能拉真实 `consensus-microdesc`；签名/权威证书校验需继续对照 dir-spec |
| Microdescriptor fetch/parse | PARTIAL | 解析与 digest 已按 spec 修正，真实网络可填充密钥；缺长期 fixture 回归 |
| Relay.IdentityKey / NtorOnionKey | PARTIAL | 现来自 microdescriptor，禁止全零 fallback；须由 fetch 成功才可用 |
| Link TLS | PARTIAL | TLS 能连上；身份不以 TLS 成功为准 |
| VERSIONS / CERTS / AUTH_CHALLENGE / NETINFO | PARTIAL | VERSIONS CircID=2 已修；CERTS ExtLen/type4 验签已按 spec+Arti 修正；AUTH_CHALLENGE 仅跳过；真实握手待 E2E |
| CREATE2 / ntor / CREATED2 | UNVERIFIED | 算法已按 spec 重写；真实 Guard CREATE2 待 E2E |
| EXTEND2 / EXTENDED2 | UNVERIFIED | 带 identity link specifier；依赖 mux 投递；待真实网络 |
| Circuit crypto / digest | PARTIAL | 有单元测试与 layered encrypt；缺 C Tor/Arti 官方 cell 向量与真实流量对照 |
| RELAY_BEGIN/CONNECTED/DATA/END | PARTIAL | 实现存在；未用真实 exit 流证明 |
| SENDME / flow control | PARTIAL | 有 window 计数；SENDME 认证与 1MB+ soak 未完成 |
| SOCKS5 | PARTIAL | CONNECT + 域名；`socks5h` 路径存在；E2E 未过 |
| DNS / RELAY_RESOLVE | PARTIAL | 有 Resolve API；未证明无本地泄漏 |
| Guard / Path selection | PARTIAL | 选路存在，不在缺 key 时静默成功 |
| Exit policy | PARTIAL | 解析/过滤有代码；未对照真实 exit 策略做互操作证明 |
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
- **缺口**：共识签名与 authority 证书的强制校验、真实 fixture 的 parse→validate 闭环仍弱。`docs/MICRODESCRIPTOR_FETCHING.md` 仍写错 `a sha256=` 行（实际是 `m` 行）。

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

### ntor / CREATE2 / EXTEND2 — UNVERIFIED（本轮已修算法 blocker）

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

**仍 UNVERIFIED：** 真实 Guard CREATE2、Middle/Exit EXTEND2。ntor-v3 未实现（经典 ntor `0x0002` 仍应被 relay 接受）。

### Circuit crypto / Relay cell — PARTIAL

- 加解密顺序：发送先 Exit 再 Middle 再 Guard；接收反向逐层 decrypt。有本地 roundtrip 测试。
- digest / recognized / stream ID / length 有实现。
- **缺口**：缺官方 C Tor/Arti relay-cell 向量；缺真实流量对照；cell tracer（`pkg/debug`，`GOTOR_CELL_TRACE=1`）默认关闭且不记用户 payload。

### SENDME / Flow control — PARTIAL

- circuit/stream window 初始值与 +100 逻辑存在。
- SENDME authentication、大流量（1MB–100MB）soak、无 hang/leak 证明：未完成。

### SOCKS5 / DNS — PARTIAL

- SOCKS5 CONNECT：域名 / IPv4 / IPv6。
- 域名应走 Exit 解析（`socks5h` / RELAY_BEGIN hostname）。
- RELAY_RESOLVE / RESOLVED 有代码。
- **未**用 `curl --proxy socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip` 证明 `IsTor=true`。

### Guard / Path / Exit policy — PARTIAL

- Guard 管理与带宽加权选路存在。
- 选路不保证已有 microdesc key；client 在 build 前 `FetchMicrodescriptorsFor`，缺 key 则失败。

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

---

## 测试

| 测试 | 作用 | 默认 `go test ./...` |
|------|------|----------------------|
| `pkg/crypto` ntor 单测 / 正确性 | HMAC + 20-byte NODEID | 运行 |
| `pkg/directory` microdesc 单测 | 同行 identity、raw digest | 运行 |
| `integration/link_test.go` | 真实 TLS+handshake | 需 `-tags=integration` + `TOR_INTEGRATION_TEST=1` |
| `integration/e2e_real_tor_test.go` | CREATE2 / 3-hop / check.torproject.org | 同上 |
| `scripts/test-real-tor.sh` | 启动 client + socks5h curl | 手动 |

`testdata/ctor-vectors/crypto/ntor_handshake.json` 与 `testdata/arti-vectors/...` 已按**正确算法重生**，目前不是从 C Tor/Arti 仓库原样导出。不得据此宣称已有官方 cross-impl 向量。

---

## 文档债务

- `ROADMAP.md` 声称 ~98% 完成、Onion/Bridge 已完成：**过期且不实**。
- `GAPS.md` 部分条目（ntor placeholder、VerifyDigest）已被 AUDIT 标为过期，但 AUDIT 未发现 ntor 算法本身错误。
- `docs/NTOR_HANDSHAKE.md` 正文仍有错误公式；文首已加警告。
- `docs/MICRODESCRIPTOR_FETCHING.md` 的 `a` 行描述过期。

---

## 第一轮完成标准（尚未达到）

只有同时满足以下全部条件，才能把 **Tor Client basic interoperability** 标为 WORKING：

1. 真实 Guard CREATE2 成功  
2. Guard → Middle EXTEND2 成功  
3. Guard → Middle → Exit circuit READY  
4. SOCKS5 → `https://check.torproject.org/api/ip` 返回 `IsTor == true` 且 IP ≠ 本机公网 IP  
5. 默认 `go test ./...` 不因公网失败  
6. `TOR_INTEGRATION_TEST=1 go test ./integration/... -tags=integration` 通过  

当前：协议主链路 blocker（含 CERTS ExtLen）已按 spec 修复；**真实网络验收仍为 UNVERIFIED**，须跑 `TOR_INTEGRATION_TEST=1`。
