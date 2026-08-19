# gotor 实现状态（按当前代码重审）

**日期**：2026-08-19  
**分支**：`cursor/family-ids-8e65`（基于 `origin/main`，纯 Go，禁止 CGO）  
**原则**：UNVERIFIED 不能算完成。文档（ROADMAP.md ~98%、AUDIT.md、GAPS.md）不可盲信，必须以仓库代码 + **现行** Tor Spec / C Tor / Arti 为准。

状态定义：

| 状态 | 含义 |
|------|------|
| WORKING | 符合 spec、有单测、且经过真实 Tor Network 验证 |
| PARTIAL | 有实现，但缺关键步骤、校验或真实网络证明 |
| BROKEN | 实现存在且会误导调用方，或协议错误到无法互操作 |
| MISSING | 无可用实现 |
| UNVERIFIED | 代码存在，但尚未用真实 Tor Network / 官方向量证明 |

**接手约定（给后续 AI）：**

1. 按**最新** tor-spec / protover 兼容实现，不要按仓库旧注释或过期 ROADMAP。
2. 100% Pure Go，禁止 CGO。入口 `cmd/tor-client`。
3. 禁止 mock 当完成、禁止全零 key fallback、禁止为过测试放松协议校验。
4. 默认 `go test ./...` 不得访问公网。真实验收：`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration`。
5. 回复、注释、文档用简体中文。提交说明写清原因、改哪里、影响。
6. 一个 PR 只做一件互操作缺口。不要把无关分支历史混进同一 PR。
7. 本文件的「未完成」节是后续工作清单。做完一项就把该项改成 WORKING，并写真实路径 / 字节数 / Guard 名。

---

## 总览（Client 主链路）

第一轮目标（真实 3-hop + SOCKS5 + `check.torproject.org` `IsTor=true`）**已达到**。现行默认握手是 ntor-v3。

对照 2026-02 共识 `recommended-client-protocols`：

`Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4`

| 组件 | 状态 | 说明 |
|------|------|------|
| Directory / Consensus | WORKING | 生产验签真实网络 9/9。证书落盘 `cached-certs`；DirCache=2 consensus diff 真实验收（CollecTor 上一小时 → 权威 limited-ed → 10193 relays） |
| Microdescriptor fetch/parse | PARTIAL | 解析与 digest 已按 spec 修正，真实网络可填充密钥；缺长期 fixture 回归 |
| Relay.IdentityKey / NtorOnionKey | PARTIAL | 现来自 microdescriptor，禁止全零 fallback；须由 fetch 成功才可用 |
| Link TLS | PARTIAL | TLS 能连上；身份不以 TLS 成功为准 |
| VERSIONS / CERTS / AUTH_CHALLENGE / NETINFO | WORKING | VERSIONS CircID=2、CERTS type4 验签、**type 7 RSA 交叉签名强制校验**、NETINFO 已在真实 Guard 通过；AUTH_CHALLENGE 客户端路径按 spec 跳过 |
| CREATE2 / ntor / CREATED2 | WORKING | 默认 ntor-v3（HTYPE 0x0003，Ed25519 主身份）；真实 Guard CREATE2 + `CC_FIELD_RESPONSE` `sendme_inc=31`。缺密钥或 `Relay<4` 回退经典 ntor |
| EXTEND2 / EXTENDED2 | WORKING | 真实 3-hop 三跳均为 ntor-v3 + FlowCtrl=2；SOCKS5 `IsTor=true`。双栈 `[01]` IPv6 已验收 |
| Circuit crypto / digest | WORKING | 真实路径已证明 AES-CTR-SHA1 与 **Relay=6 CGO** |
| RELAY_BEGIN/CONNECTED/DATA/END | WORKING | 真实 exit 流已拉取 check.torproject.org |
| SENDME / flow control | WORKING | FlowCtrl=2 TOR_VEGAS；1MB **1059120** + 10MB **10497056** + 多流 **753152** 真实验收；电路未 DESTROY |
| SOCKS5 | WORKING | SOCKS5 + `https://check.torproject.org/api/ip` 已返回 `IsTor=true` |
| DNS / RELAY_RESOLVE | WORKING | 真实 3-hop RESOLVE 得 IPv4+IPv6；本机 resolver 不可达仍成功 |
| Guard / Path selection | PARTIAL | 选路存在，不在缺 key 时静默成功；family-ids（Desc=4）已用于避让，待真实验收 |
| Exit policy | WORKING | 已解析 `p`/`p6` 与完整 accept/reject；IPv6 字面量按 p6 选路。`TestRealExitPolicyP6` 通过（2026-08-19：抽样 64 Exit，p=64 p6=51，选路 Exit=`eisbaer`） |
| Relay=5 subproto_request | WORKING | 真实 CREATE2/EXTEND2 发出 type 3 `[02 06]`，对端接受并启用 CGO |
| Relay=6 CGO | WORKING | 真实 3-hop CGO + `IsTor=true` + soak **1059120** 字节 |
| Conflux=1 | WORKING | 真实双电路 LINK + SOCKS `IsTor=true` ExitIP=`192.42.116.116`（2026-08-19） |
| Circuit padding (Padding=2) | PARTIAL | 有定时器骨架，无 HS setup machine（proposal 302） |
| Onion Service v3 | BROKEN / MISSING | **明确不做**，直到 client 主链路剩余缺口完成 |
| Relay / Bridge | BROKEN / UNVERIFIED | **明确不做**；服务端 ntor 仍可能用错 NODEID |
| Control Protocol | PARTIAL | 框架存在，非本轮验收 |
| Pluggable Transport | PARTIAL | 框架，非本轮验收 |

---

## 未完成（给后续 AI，按最新 Tor 优先）

下列是**还没做完**、需要按现行 spec / C Tor / Arti 继续实现的项。不要把骨架或 mock 标成 WORKING。

### P0 — 现行推荐客户端仍缺的互操作

#### 1. FlowCtrl=2 Vegas（完整拥塞控制）

- **状态**：WORKING（1MB 真实验收已过）。状态机按 proposal 324 / C Tor；`sendme_inc` 只来自握手。
- **已做**：
  - RTT（SENDME 对应 DATA 的发出时刻）、N-EWMA、clock stall/jump
  - BDP = `cwnd * min_rtt / ewma_rtt`，`queue_use = cwnd - BDP`
  - RFC3742 Limited Slow Start；CA 的 delta/beta/alpha；`inflight`；`cwnd_full` 启发式
  - 共识 `params` 经 `LastConsensusParams` 注入（Exit 阈值 `cc_vegas_*_exit`）
  - 单测：`pkg/circuit/vegas_test.go`、`ccparams_test.go`
  - 真实 soak：`TestRealFlowControlSoak` **1059120** 字节，Guard `rafsnicesrelay` → Middle `janina1` → Exit `NTH66R5`，三跳 `sendme_inc=31`，电路未 DESTROY
- **剩余**：orconn 阻塞已按 TLS 写排队/慢写采样；更大 soak 见 P0.2
- **Spec**：https://spec.torproject.org/proposals/324-rtt-congestion-control.html ；tor-spec flow-control
- **C Tor**：`src/core/or/congestion_control_common.c`、`congestion_control_vegas.c`
- **现有代码**：`pkg/circuit/vegas.go`、`pkg/circuit/ccparams.go`、`pkg/circuit/sendme.go`

#### 2. 更大流量 soak + SENDME 回归

- **状态**：WORKING（2026-08-19）。
- **已做**：
  - `SendRelayCell` 在电路/流窗口用尽时等待 SENDME，而不是立刻失败
  - OR 连接 `WriteBlocked()`：发送排队 >1，或单次 TLS 写出 ≥100ms（只报一次，避免 sticky 误伤 Vegas）
  - Stream Manager 按 `(circuitID, streamID)` 索引（修复多电路并发撞号）
  - 集成：`TestRealFlowControlSoak10MB`、`TestRealFlowControlMultiStream`、`TestRealFlowControlSoak100MB`（需 `TOR_SOAK_100MB=1`）
- **真实网络（2026-08-19）**：
  - `TestRealFlowControlSoak10MB`：**10497056** 字节，ok_rounds=446，fail_rounds=1，电路未 DESTROY
  - `TestRealFlowControlMultiStream`：4 流合计 **753152** 字节；无 `stream ID already in use`
- **现有代码**：`pkg/circuit/sendme.go`、`pkg/connection/connection.go`、`pkg/stream/stream.go`、`integration/e2e_real_tor_test.go`

### P1 — 最新电路加密方向（尚未 required，但 mainnet 已宣告）

#### 3. Relay=5 `subproto_request`（proposal 346）

- **状态**：WORKING。真实握手发出 type 3 `[02 06]`，对端接受。
- **已做**：
  - type 3 DATA：`{protocol_id u8, cap u8}*`，升序；Relay=6 = `[02 06]`
  - 只允许现行表内能力（目前仅 `RELAY_CRYPT_CGO`）
  - 选择：`Relay=5` ∧ `Relay=6` ∧ `FlowCtrl=2` ∧ `ImplementedNegotiableCaps()`
  - `ImplementedNegotiableCaps()` 含 CGO
- **Spec**：https://spec.torproject.org/tor-spec/create-created-cells.html ；https://spec.torproject.org/proposals/346-protovers-again.html
- **现有代码**：`pkg/crypto/subproto.go`、`pkg/crypto/ntorv3.go`、`pkg/circuit/extension.go`
- **禁止**：对未宣告 Relay=5/6 的节点发 type 3。

#### 4. Relay=6 CGO（Counter Galois Onion）

- **状态**：WORKING。
- **已做**：
  - POLYVAL（RFC 8452 + C Tor ctmul64 约化）
  - ET / PRF / UIV+；客户端 DEC_UIV；`CGO_AES_BITS=128`（**不是** AES-256）
  - 每方向 80 字节，双向 KDF **160** 字节（`cgo_key_material_len(128)*2`）
  - v1 relay message（C Tor `relay_msg.c`：cmd@16、len@17、可选 stream_id@19）
  - DATA 上限 488（509-21），不是 v0 的 498
  - SENDME v1 DATA_LEN=16（CGO tag T）；CGO hop 上不发流级 SENDME
  - 混合电路：逐跳 CGO 或 tor1，未协商成功禁止回退
  - 官方向量：`pkg/crypto/cgo_test.go`（C Tor `cgo_vectors.inc`）
- **真实网络（2026-08-19）**：
  - CREATE2：Guard `SENDNOOSEplz`，`cgo=true`，`sendme_inc=31`
  - 3-hop：`llorona` → `Bluejaybrd` → `DFRI18`，三跳 `hop_cgo=true`
  - SOCKS5 `IsTor=true`，ExitIP=`192.42.116.21`（`rafsnicesrelay` → `booth` → `NTH21R3`）
  - soak **1059120** 字节，电路未 DESTROY（`rafsnicesrelay` → `Art3mis` → `r0cket09i7`）
- **Spec**：https://spec.torproject.org/proposals/359-cgo-redux.html
- **C Tor**：`relay_crypto_cgo.c`、`relay_crypto.c`（`CGO_AES_BITS 128`）、`src/test/cgo_vectors.inc`
- **禁止**：未协商成功时偷偷回退到 AES-CTR 还宣称 CGO WORKING。
- **注意**：2026-02 `recommended-client-protocols` 仍是 `Relay=2-4`。不要对未宣告 `Relay=5/6` 的 hop 强制请求。

### P2 — 已广泛宣告、提升兼容与匿名性

#### 5. Conflux=1（proposal 329）

- **状态**：WORKING。纯 Go：`pkg/cell/conflux.go`、`pkg/circuit/conflux.go`、`pkg/path/conflux.go`。
- **Spec**：https://spec.torproject.org/proposals/329-traffic-splitting.html
- **要点**：命令 19–22；LINK/LINKED 50 字节大端；UX=3 + LowRTT；OOO 上限 256。
- **选择**：两条腿 Guard/Middle/Exit 均宣告 `Conflux=1` **或** `Conflux=2`（mainnet 常见只写 2；flag 不蕴含），且都已协商 FlowCtrl=2。同一 Exit，不同 Guard/Middle（身份键，且不得与第一腿 Guard/Middle 同 family 或同 /16）。
- **关路**：`Close` / `CloseCircuit` / 池丢弃 / 远端 DESTROY / 协议错误都会拆掉两条腿；不得只 `SetState`。
- **收包**：LINKED / SWITCH / 多路信元只接受 Exit hop；SWITCH 要求已 LINK、`rel>=1`、合法 gap，且不得来自当前 receive 领先腿；OOO 同序号不得覆盖。
- **禁止**：未完成 LINK 把单电路标成 Conflux；日志写出 nonce；未协商 FlowCtrl=2 却 LINK。
- **真实网络（2026-08-19 `TestRealConflux`）**：
  - LINK：`TorNode07dot4` → `pecord` → `r0cket08i3` 与 `cryzrelay01` → `Orrion` → `r0cket08i3`（同 Exit，不同 Guard/Middle）
  - LINKED RTT 384ms / 430ms，随后 LINKED_ACK
  - SOCKS5 `https://check.torproject.org/api/ip`：`IsTor=true`，ExitIP=`192.42.116.116`

#### 6. EXTEND2 IPv6（Relay=3）

- **状态**：WORKING。纯 Go：共识 `a` 行 → `Relay.IPv6`；`buildExtend2Data` 在双栈且 `Relay=3` 时追加 `[01]`（LSLEN=18，大端端口）。
- **Spec**：tor-spec create-created-cells / EXTEND2 specifier `[01]` IPv6；subprotocol `RELAY_EXTEND_IPv6`
- **要点**：顺序 `[00] [02] [03] [01]`；`Relay=4` 不蕴含 `Relay=3`；IPv4-only 仍 NSPEC=3；兼容旧 `a sha256=`。
- **禁止**：无 IPv6 ORPort 硬塞 `[01]`。
- **现有代码**：`pkg/directory/oraddress.go`、`pkg/circuit/extension.go`；文档 `docs/interop/extend2-ipv6.md`
- **真实网络（2026-08-19 `TestRealExtend2IPv6`）**：
  - 共识 10186 个中继，其中 **5532** 个有 IPv6 ORPort，全部宣告 `Relay=3`
  - Guard `NTH115R1` → Middle `prsv`（`[2001:41d0:701:1100::7a21]:9200`）→ Exit `DFRI80`（`[2001:67c:289c:2::40]:80`）
  - 两次 EXTEND2 均为 NSPEC=4，dump 含 `[01]` + 16 字节 IPv6 + 大端端口；EXTENDED2 成功，3-hop READY

#### 7. Exit policy IPv6 `p6` + 完整 `p` 行

- **状态**：WORKING（2026-08-19 真实验收）。
- **已做**：
  - microdesc / 共识解析 `p6`；缺 p6 ≡ `reject 1-65535`
  - server descriptor 完整 `accept`/`reject`（CIDR、点分掩码、`[IPv6]`、`*`/`*4`/`*6`）；无匹配则接受
  - `ipv6-policy` 摘要；`CanExitTo` 按地址族分流，IPv4 `*` 不得放行 IPv6
  - `SelectPathFor` / Conflux / 预建补齐 microdesc 后按目标重选
  - 电路绑定 ExitFilter；SOCKS IPv6 用 `[addr]:port`，池中按策略取电路
- **真实网络（2026-08-19 `TestRealExitPolicyP6`）**：
  - 共识约 10193 中继；抽样 64 Exit：`p=64`、`p6=51`、`allow_ipv6_443=51`
  - `SelectPathFor(2001:db8::1:443)` → Exit `eisbaer`，`p6=true` 且允许 443
  - 审计：缺 p6 拒绝 IPv6；`*`/`*4` 不放行 IPv6；`encodeBeginAddrPort` 对 IPv6 带方括号
- **现有代码**：`pkg/directory/exitpolicy.go`、`exitrules.go`；`pkg/path`；`pkg/circuit/exitfilter.go`；`docs/interop/exit-policy.md`

#### 8. Circuit padding machine（Padding=2 / proposal 302）

- **状态**：PARTIAL。`Circuit` 有 padding 间隔字段，不是 HS setup machine。
- **Spec**：https://spec.torproject.org/padding-spec ；proposal 302
- **验收**：对照 C Tor machine 状态表的单测。不要发明与 spec 不符的随机 padding 并宣称合规。

#### 9. Consensus diff（DirCache=2）

- **状态**：WORKING（2026-08-19 真实验收）。
- **已做**：
  - `network-status-diff-version 1` + `hash FromDigest ToDigest`（SHA3-256）
  - FromDigest = 旧文档 signed part；ToDigest = 应用后整份新共识
  - 只接受 `d`/`c`/`a`；有签名时第一条必须是首个 `directory-signature` 行的 `n,$d`
  - 有缓存时发 `X-Or-Diff-From-Consensus`；apply / 验签失败则同一权威去掉 header 重拉整份
  - **去掉 CollecTor `@type` 前缀**（否则 Diff 行号整体 +1，真实 `N,$d` 失败）
  - `LastFetchUsedDiff` / `LoadVerifiedConsensusDocument` / `TryConsensusDiffFromAuthority` 供验收
  - 未验签结果不入缓存；单测 + httptest（不访问公网）
- **真实网络（2026-08-19 `TestRealConsensusDiff`）**：
  - 灌入 CollecTor `2026-08-19-10-00-00-consensus-microdesc`（10156 relays）
  - 权威 `moria1` 返回 limited-ed diff 并 apply + 验签 → **10193** relays；`LastFetchUsedDiff=true`
  - 二次 `FetchConsensus` 回退整份成功
- **Spec**：https://spec.torproject.org/dir-spec/directory-cache-operation.html ；limited-ed-diff-format
- **现有代码**：`pkg/directory/consdiff.go`；`pkg/directory/directory.go`；文档 `docs/interop/consensus-diff.md`

#### 10. 权威证书落盘 + 官方长期 fixture

- **状态**：PARTIAL（`cached-certs` 落盘 + 加载重验签；官方长期 fixture 仍缺）。
- **已做**：
  - 启动时读 `DataDirectory/cached-certs`（C Tor 拼接文本格式）
  - 加载时强制 KnownAuthorities + certification/crosscert + 未过期
  - 验签成功的证书原子写入（临时文件 + rename，`0600`）
  - 损坏/超大文件不阻断启动；过期与未知权威跳过
  - 可用性以 `dir-key-expires` 为准
  - 离线单测：落盘重载不访问 HTTP；过期必须失败
- **未做**：从 C Tor/Arti 导出的不可变实网证书（实网证书会过期，不得当长期 fixture）
- **现有代码**：`pkg/directory/certcache_disk.go`；文档 `docs/interop/authcert-cache.md`
- **验收**：离线 fixture 验签；证书过期必须失败。真实重启后少拉 `/tor/keys/fp` 再标 WORKING。
- **禁止**：为过测试放宽过期检查；把过期/未知权威证书当成功缓存；C 库 / CGO。

### P3 — 向量、选路、文档债务（不阻塞主链路，但不得宣称「已有官方向量」）

#### 11. 官方 C Tor / Arti 原样向量

- `testdata/ctor-vectors/crypto/ntor_handshake.json` 与 `testdata/arti-vectors/...` 是按**正确算法重生**的，不是从上游仓库原样导出。
- 需要：从 C Tor / Arti 测试文件原样拷贝 ntor、ntor-v3、relay-cell、CGO 向量。
- **禁止**据此宣称已有官方 cross-impl 向量。

#### 12. Family ID（Desc=4）

- **状态**：PARTIAL（microdesc `family-ids` + `InSameFamily`；未跑真实网络）。
- **已做**：
  - 解析 `family-ids`（含未识别格式）；共享任一 ID 即同家族
  - 旧 `family` 列表仍要求双向；支持 `$HEX` / `$HEX=name` / `$HEX~name`
  - 共识 `use-family-ids` / `use-family-lists`（缺省 1）
  - 选路与 Conflux 第二腿走同一判断
  - 建路前（及 Conflux 第二腿）在 microdesc 补齐后重验，冲突则重选
- **未做**：从 server descriptor 的 `family-cert` 本地导出 ID（microdesc 客户端不需要）
- **Spec**：path-spec determining family membership；dir-spec family-ids；proposal 321
- **现有代码**：`pkg/directory/family.go`；文档 `docs/interop/family-ids.md`
- **验收**：同一 family ID 不会出现在同一条电路的多个 hop。真实验收后标 WORKING。
- **禁止**：忽略 family-ids 只靠 nickname；为过测试放松双向列表；C 库 / CGO。

#### 13. 文档债务

- `ROADMAP.md` 声称 ~98% 完成、Onion/Bridge 已完成：**过期且不实**。
- `GAPS.md` 部分条目过期。
- `docs/NTOR_HANDSHAKE.md` 正文仍有错误公式；文首已加警告。
- `docs/MICRODESCRIPTOR_FETCHING.md` 仍可能写错 `a sha256=`（实际是 `m` 行）。

### 明确不做（在 P0/P1 完成前不要开做）

| 项 | 原因 | 已知坑 |
|----|------|--------|
| Onion Service v3 | 主链路最新协议尚未对齐 | hs-ntor 未做；`BuildRendezvous1Cell` 曾误用 circuit ntor + 32 字节 Ed25519 |
| Relay 服务端 | 本仓库目标是 client | `pkg/relay/circuit_handler.go` 可能把 Ed25519 当 ntor NODEID |
| Bridge / PT 生产路径 | 非本轮 | 框架存在，UNVERIFIED |

若要做 HS：必须先实现 **hs-ntor**（不是 circuit ntor），再 HSDir v3、INTRODUCE/RENDEZVOUS。对照 rend-spec-v3 与 C Tor `hs_ntor.c` / Arti `hs_ntor`。

---

## 分类明细（已完成部分）

### Directory / Consensus — PARTIAL

- 默认拉 `consensus-microdesc`（当前 Tor Network 默认格式）。
- `r` 行 identity 按 **无 padding base64** 解成 20 字节 `RSAIdentity`，并提供 40 字符大写 hex 给 CERTS。
- `valid-after` / `fresh-until` / `valid-until`、flags、bandwidth、`m` digest 有解析。
- Authority 列表已更新到当前公开 IP。
- 生产 `FetchConsensus` 在 metadata 之外强制 `VerifyConsensusSignatures`：`/tor/keys/fp/<id>`、`dir-signing-key`、`dir-key-certification`、`dir-key-crosscert`、majority（5/9）。
- 权威证书落盘 `DataDirectory/cached-certs`；加载时重验签，过期拒绝。见 `docs/interop/authcert-cache.md`。
- DirCache=2：有缓存时请求 limited ed consensus diff；apply / 验签失败回退整份。见 `docs/interop/consensus-diff.md`。
- `r` / `valid-*` / `params` 只解析 signed body；未签名前缀/后缀不得注入 relay 或改写有效期。
- 真实网络：`TestRealConsensusSignatures` 验证 **9/9** 权威签名，共识含约 10143 个 relay。
- 详见 `docs/interop/consensus.md`。

### Microdescriptor — PARTIAL（解析 blocker 已修）

**曾经 BROKEN：** `id ed25519` 读成下一行；digest 带 padding；串行拉取 + 过短 timeout。

**现在：** `pkg/directory/microdesc.go` 并行拉取、正确 digest、同 extra 行解析 ntor / ed25519 / family / policy。缺 key **报错**，不用 `make([]byte,32)`。

详见 `docs/interop/microdescriptor.md`。

### Relay.IdentityKey / NtorOnionKey — PARTIAL

- `NtorOnionKey`：microdescriptor `ntor-onion-key`。
- `IdentityKey`：microdescriptor `id ed25519`（32 字节，给 EXTEND2 `[03]` 与 ntor-v3 ID）。
- `RSAIdentity`：共识 `r` 行（20 字节，经典 ntor NODEID + EXTEND2 `[02]`）。
- `HasNtorKeys()` / `HasExtendKeys()` 拒绝全零。

### Link VERSIONS CircID 宽度 — 已修

VERSIONS 必须 `CIRCID_LEN(0)=2`，协商后再切 4 字节。见 `docs/interop/link-versions.md`。

### Link protocol / CERTS — WORKING（含 type 7）

- 顺序：VERSIONS → CERTS →（跳过 AUTH_CHALLENGE/PADDING）→ NETINFO。
- **不能**把 TLS 成功当成 identity 验证成功。
- 主身份是 Ed25519。type 7 用遗留 RSA-1024（type 2）做 PKCS#1 交叉签名，绑到共识指纹。
- 哈希：`SHA256("Tor TLS RSA/Ed25519 cross-certificate" || KEY || EXP)`（**36 字节，不含 SIGLEN**）。cert-spec 字面含 SIGLEN，以 C Tor / 真实 CERTS 为准。
- `rsa.VerifyPKCS1v15(pub, 0, hash, sig)`；缺 type 2 或验签失败为硬错误。
- RSA **不**加密流量、**不**协商电路密钥。
- 真实网络：`TestRealCertsType7RSA`（Guard `SENDNOOSEplz`）。
- 详见 `docs/interop/certs.md`。

### ntor / CREATE2 / EXTEND2 — WORKING（默认 ntor-v3 `0x0003`）

实现见 `pkg/crypto/ntor.go`、`pkg/crypto/ntorv3.go`、`docs/interop/ntor.md`、`docs/interop/ntor-v3.md`。

**现行默认：** 有 Ed25519 且 `Relay=4`（或缺 pr）→ ntor-v3。`FlowCtrl=2` → `CC_FIELD_REQUEST`。经典 ntor `0x0002` 仅作回退。

生产 verification 必须是 `"circuit extend"`（14 字节，无 NUL）。空串或 proposal 332 测试串 `xyzzy` 都会让服务端 phase1 MAC 失败并 DESTROY reason=1。

**真实网络（2026-08-19）：**

- HTYPE=3，三跳 ntor-v3 + `sendme_inc=31`
- `IsTor=true`，ExitIP=`185.244.192.184`（Quetzalcoatl）
- soak **1059120** 字节未拆路（FlowCtrl=2 Vegas）

### Circuit crypto / Relay cell — WORKING（AES-CTR-SHA1 与 CGO）

- 发送先 Exit 再 Middle 再 Guard；接收反向逐层 decrypt。
- 真实 RELAY_DROP 不再触发 DESTROY。
- **Relay=6 CGO**：AES-128 UIV+、v1 cell、DATA 上限 488。真实 3-hop + `IsTor=true` + soak 1059120。
- **缺口**：官方 v0 relay-cell 向量。

### SENDME / Flow control — WORKING

- 未协商 CC：circuit window 1000 / +100；stream 500 / +50。
- 电路级 SENDME v1：DIGEST=触发 cell 的完整 20 字节滚动 SHA-1；FIFO 匹配失败拆路。
- 协商 CC 后启用 TOR_VEGAS：间隔 `sendme_inc`，初始 cwnd=`cc_cwnd_init`（默认 124，不是 186）。
- 流级 SENDME 仍为空（spec）。
- **真实网络（2026-08-19）**：
  - 1MB soak：**1059120** 字节（历史）
  - 10MB soak：**10497056** 字节，ok=446 / fail=1，未 DESTROY
  - 多流：**753152** 字节（4 流）；StreamID 按电路索引后无撞号
- 可选：`TOR_SOAK_100MB=1` 超大 soak（不阻塞 WORKING）。

### SOCKS5 / DNS — WORKING

- CONNECT 把 hostname 放进 RELAY_BEGIN（socks5h），生产路径禁止 `net.Lookup*`。
- RESOLVE：非 0 StreamID、arpa PTR、多条应答。
- 真实：`www.torproject.org` → `116.202.120.166` + IPv6；PTR → `web-fsn-02.torproject.org`。

### Guard / Path / Exit policy — PARTIAL（Exit policy 已 WORKING）

- build 前 `FetchMicrodescriptorsFor`，缺 key 则失败。
- 预建按端口 443 选 exit；禁止把非 Exit 当 fallback。
- IPv6 字面量按 `p6` 选路；缺 p6 拒绝。完整 `accept`/`reject` 已解析。
- 选路按 `family-ids` 与双向 `family` 列表避让；见 `docs/interop/family-ids.md`。
- **Exit policy**：`TestRealExitPolicyP6` 已通过（2026-08-19）。

---

## 已修的最高优先级 blocker（历史）

| # | Blocker | Root cause | Spec / 参考 |
|---|---------|------------|-------------|
| 1 | ntor 无法与 mainnet 握手 | H 误实现为 HKDF；NODEID 用错 | create-created-cells；`onion_ntor.c`；Arti `ntor.rs` |
| 2 | microdesc 密钥匹配失败 | digest padding；`id ed25519` 换行解析 | dir-spec microdescriptor |
| 3 | zero-key fallback | 缺 key 仍 `make([]byte,32)` | 禁止静默 fallback |
| 4 | 生产路径无 link handshake | 只做 TLS | negotiating-channels |
| 5 | EXTENDED2 无人投递 | 无 mux | 连接上多 circuit cell 分发 |
| 6 | Building 不能发 RELAY | `SendRelayCell` 只允许 Open | EXTEND2 必须在 build 期间发送 |
| 7 | CircID 被拒 | MSB 未置 1 | link proto ≥4 |
| 8 | EXTEND2 缺 identity specifier | 只发 IPv4 | `[00][02][03]` |
| 9 | VERSIONS 超时 | CircID 用 4 字节 | CIRCID_LEN(v=0)=2 |
| 10 | CERTS type 4 验签失败 | ExtLen 含 type+flags；identity 误用 signing key | cert-spec；Arti `tor-cert` |
| 11 | EXTEND2 超时 | RELAY `Length` 未设 | relay-cells |
| 12 | EXTEND2 DESTROY reason=1 | 对 KEY_SEED 二次 HKDF-Extract | IKM=`secret_input` |
| 13 | 预建电路假就绪 | sleep 1s 后宣称已建好 | Start 与 WaitUntilReady 分离 |
| 14 | HTTPS 选到只放行 80 的 exit | `SelectPath(80)` 且只看 Exit flag | 预建 443；解析 `p` 行 |
| 15 | 大流量 DESTROY | 电路级 SENDME 发空 v0 | SENDME v1 |
| 16 | 共识只数签名个数 | `VerifyConsensusSignatures` 未被调用 | dir-spec authority certs |
| 17 | RELAY_RESOLVE 被丢掉 | StreamID=0；PTR 发二进制 | remote-hostname-lookup |
| 18 | 验签未绑定解析结果 | 解析了未签名后缀 | 只解析 signed body |
| 19 | SENDME 竞态 / 重复发出 | 减窗与记 tag 分锁 | 原子减窗 |
| 20 | CREATE2 waiter 竞态 | 先发后登记 waiter | ExpectCreated2 在发送前 |
| 21 | 仍默认经典 ntor | 有扩展必须 ntor-v3 | onion_ntor_v3.c |
| 22 | CERTS type 7 未验 RSA 绑定 | Ed25519 可被替换而指纹仍匹配 | cert-spec RSA→Ed25519 cross-cert |

---

## 测试

| 测试 | 作用 | 默认 `go test ./...` |
|------|------|----------------------|
| `pkg/crypto` ntor / ntor-v3 | 经典 HMAC NODEID；proposal 332 官方向量 | 运行 |
| `pkg/directory` microdesc / 共识验签 | digest、自生成证书、篡改必失败 | 运行 |
| `pkg/protocol` CERTS type 7 | RSA→Ed25519 交叉签名；缺 type 2 / 篡改必失败 | 运行 |
| `integration/link_test.go` | 真实 TLS+handshake / type 7 RSA | `-tags=integration` + `TOR_INTEGRATION_TEST=1` |
| `integration/e2e_real_tor_test.go` | 共识验签 / ntor-v3 CREATE2 / 3-hop / IsTor / soak / RESOLVE / Conflux / EXTEND2 IPv6 / p6 选路 | 同上 |
| `scripts/test-real-tor.sh` | 启动 client + socks5h curl | 手动 |

---

## 第一轮完成标准（已达到：ntor-v3 + AES-CTR-SHA1）

1. 真实 Guard CREATE2 成功  
2. Guard → Middle EXTEND2 成功  
3. Guard → Middle → Exit circuit READY  
4. SOCKS5 → `https://check.torproject.org/api/ip` 返回 `IsTor == true`  
5. 默认 `go test ./...` 不因公网失败  
6. `TOR_INTEGRATION_TEST=1 go test ./integration/... -tags=integration` 通过  

**下一轮完成标准：** DirCache=2 consensus diff / Desc=4 family-ids / authcert 重启真实验收（Phase 1.3–1.5）；其后 Padding=2（Phase 2）。
