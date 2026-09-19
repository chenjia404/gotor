# gotor 与官方 Tor 的兼容差距

**日期**：2026-09-19  
**对照官方版本**：C Tor **0.4.9.11**、Arti **2.6.0**（2026-09-01，[官方博文](https://blog.torproject.org/arti_2_6_0_released/)）  
**说明**：C Tor **0.4.8 已 EOL**，不要再按 0.4.8 行为实现或宣称兼容。  
**对照范围**：**同时**对照 C Tor 与 Arti，不能只盯 C Tor。官方新协议/新特性以 Arti changelog 为优先观察源，落地仍以共识与 mainnet 互操作为准。  
**代码依据**：[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) + 仓库代码 + 真网/权威观察。  
**不要盲信**：[`ROADMAP.md`](../ROADMAP.md) 里的「~98% 完成」「Onion/Bridge 已完成」。

状态用语（与 `IMPLEMENTATION_STATUS.md` 对齐）：

| 标记 | 含义 |
|------|------|
| 已对齐 | 符合现行 spec，且有真网或官方向量证据 |
| PARTIAL | 有代码，但缺关键步骤、接线、或真网证明 |
| 官方有我们没有 | 官方 C Tor / Arti 具备，gotor 无可用实现 |

禁止事项对**每一项后续实现**都适用：禁止全零 key fallback、禁止 mock/本地桩当完成、禁止为过测试放松协议校验、禁止未协商却宣称 CGO、禁止把「ORPort 通了」写成「已进共识」。
公开 PR / commit **禁止** 写真实服务器名、公网 IP、中继指纹、联系人、内网仓库地址。真网观察用「实验中继」「权威已收描述符」「缺 Running」等不带识别信息的说法。

---

## 声明

gotor **不是** Tor Project 官方实现，也未受其监督或背书。  
**不能当作人身安全级匿名工具。** 需要匿名时请用 [Tor Browser](https://www.torproject.org/download/) 或官方 [Arti](https://gitlab.torproject.org/tpo/core/arti) / [C Tor](https://gitlab.torproject.org/tpo/core/tor)。

---

## 一句话定位

**客户端接近官方推荐协议；中继实验性（描述符可被权威收下；入站握手 + self-test + 中间跳出站握手已接线，Running / 真网被选为中间跳仍取决于权威与可达性）；洋葱托管未上线。**

---

## Arti 现行角色（约 2.5.1）

资料：[Arti 2.5.1 博文](https://blog.torproject.org/arti_2_5_1_released/)、[2.5.0 博文](https://blog.torproject.org/arti_2_5_0_released/)、[2.4.0 博文](https://blog.torproject.org/arti_2_4_0_released/)、[CHANGELOG.md](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CHANGELOG.md)（1.0.0–2.2.0 等已收录章节；2.5.x 以博文与 changelog 补丁为准）。

| 角色 | Arti 2.5.1 | 对 gotor 的含义 |
|------|------------|-----------------|
| **客户端** | 可生产：1.0.0（2022-09）起 `arti-client` / SOCKS 即稳定路径；**2.6.0 起拥塞控制与 CGO 在 `arti` 中始终启用**（去掉 `flowctl-cc` / `counter-galois-onion` cargo feature） | gotor 客户端应对齐 **共识 recommended** 与 Arti/C Tor **都已在 mainnet 用的** 握手，而不是 Arti 实验 cargo feature |
| **洋葱** | **有**：托管自 1.2.0（2024-03）起 `onion-service-service` 非实验；2.5.1 增加 AF_UNIX 后端，HS 上的拥塞控制/CGO 仍是实验 feature（`hsc-negotiate-extensions` / `hss-negotiate-extensions`，[#1948](https://gitlab.torproject.org/tpo/core/arti/-/issues/1948)、[#2473](https://gitlab.torproject.org/tpo/core/arti/-/issues/2473)） | gotor 托管未上线；不要把 Arti 实验 HS-CGO 开关写成「官方已 required」 |
| **中继** | **仍在做**：2.0.0 起电路 reactor / TLS 服务端；2.2.0「更接近可用 middle」；2.5.1 继续（入向消息校验、BeginDir/Resolve、未完成的 `DirMirror`、描述符生成与上传）；**2.6.0** CREATE2 ntor-v3、目录镜像/权威文档解析推进。**还不能当生产中继**，生产中继仍要 C Tor | gotor 中继同样是实验性；跟 `required-relay-protocols`，不要复制 Arti 未完成的内部类型 |
| **目录权威** | **仍在做**：2.0.0 起证书管理；2.5.0 编解码 router/microdesc/consensus；2.5.1 开始算共识、以及给 C Tor 权威用的插件雏形 | gotor **不做** DirAuth |
| **控制面** | **RPC 稳定**（1.4.2，2025-03），**不**再实现 C Tor control-spec。嵌入走 `arti-client` | gotor 走 C Tor 风格控制口 + Go 库 API；不要为追 Arti RPC 拆掉已有 control-spec 子集 |

---

## 跟进原则（C Tor / Arti / 共识）

1. **观察源**：官方新功能优先读 [Arti CHANGELOG](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CHANGELOG.md) 与 [arti 博文](https://blog.torproject.org/category/arti/)，再对照 C Tor ChangeLog。
2. **落地源**：gotor 跟 **现行共识 `recommended-*` / `required-*`**，以及 **mainnet 已宣告且 C Tor 与 Arti 都在用的** 能力（例如 ntor-v3、FlowCtrl=2、客户端 CGO）。
3. **不要追实验开关**：Arti 的 `hsc-negotiate-extensions`、`circ-padding-manual`、未标 stable 的 conflux 后端等，**禁止**为了对齐 cargo feature 而破坏与 C Tor 0.4.9.11 / 现网中继的互操作。
4. **角色差**：Arti 洋葱托管已上线、中继未上线；gotor 洋葱托管未上线、中继也未进共识。不能把「Arti 有」直接写成「gotor 该立刻做完」。

---

## 按角色对照

| 角色 | 已对齐（含真网证据） | PARTIAL | 官方有我们没有 |
|------|----------------------|---------|----------------|
| **客户端** | 共识 9/9 验签、`cached-certs` 重启 0 次 `/tor/keys/fp`、DirCache=2 consdiff、microdesc、Link TLS+CERTS type 7、默认 ntor-v3 CREATE2/EXTEND2、3-hop SOCKS5 `IsTor=true`、RESOLVE、FlowCtrl=2 Vegas soak、Relay=5/6 CGO、Conflux=1、EXTEND2 IPv6、`p`/`p6` 出口策略、Desc=4 family-ids、Padding=2 协商 ACK、v3 `.onion` 客户端 HTTP 200 | Guard 选路与官方指纹仍可能有差异；Fast/MiddleOnly/BadExit 已强制但未单独真网标 WORKING；circpad token-removal；**vanguards 客户端 L2+L3**（读共识 `guard-hs-l*`；无托管侧）；**洋葱 PoW 客户端**（无真网 PoW 服务验收） | 托管侧 vanguards；完整 PT/网桥客户端生产路径；与 Tor Browser 同级的隔离/反指纹 |
| **中继** | 描述符可 POST 到权威并获 HTTP 200；交叉证书（onion-key-crosscert / ntor-onion-key-crosscert）与 Ed25519 摘要签名按 dir-spec 生成；**proto 只宣告已实现的 Cons/Desc/Microdesc/Link/LinkAuth/Relay/FlowCtrl** | ORPort 监听；入站握手 CERTS/AUTH_CHALLENGE/NETINFO；**LinkAuth=3 校验 AUTHENTICATE type 3，AUTH_CHALLENGE 只广告方法 3**；ORPort self-test 门闩（未测活不发布；`AssumeReachable` 跳过探测）；CREATE2 经典 ntor / ntor-v3；**ntor-v3 type 3 `[02 06]` 则 CGO 剥层/回程 + 出口 SENDME v1（16 字节 tag FIFO）**（未宣告 Relay=5-6）；中间跳出站握手（VERSIONS/CERTS/NETINFO）+ CircID MSB + 按身份入池；EXTEND2 剥层转发与回程加密（离线单测）；出口策略解码与 EXIT 流（实验）；DirPort/BEGIN_DIR 可服务 **ns 与 microdesc 分库**、micro/all、`/tor/keys`、**最多 72 小时历史→当前 limited-ed**、**gzip/deflate/`.z` / 304**、**FPRLIST 签名过滤**、**x-zstd / x-tor-lzma**、**预压缩 consdiff 库**（未宣告 DirCache=2）；末端跳 ESTABLISH + **INTRODUCE1→INTRODUCE2 / RENDEZVOUS1→RENDEZVOUS2** + **HSDir `/tor/hs/3` 验签收/服 + 哈希环 spread_store + 引言点令牌桶**（未宣告 HS*）；**extra-info-digest 交叉引用 + 观测带宽历史**（入站 OR + 出站中间跳；无观测不写 history）+ **conn-bi-direct / ipv6-conn-bi-direct（满 24h 才写）** + **dirreq-v3-resp / dirreq-v3-ips / dirreq-v3-reqs / dirreq-v3-direct-dl / dirreq-v3-tunneled-dl（满 24h 才写；ips/reqs 仅 ??；dl 仅 complete）** + **exit-*（满 24h 才写；BEGIN_DIR 不计）**；**官方 DoS* 键 + CREATE2/每 IP + auto 跟共识 + ConnectRate/Burst + StreamCreation + AUTHENTICATE 单跳区分 + CircuitCreationDefenseType + 共识 nodelist 核对身份**（默认 auto 关） | **进共识 `Running`**；真网被官方客户端选为中间跳的证据；对外宣告 DirCache=2（真网被当缓存）；真网被选为 intro/rend/HSDir；HS* proto（extra-info hidserv / 真网被选）；真网被请求 CGO 的证据；完整 dos.c（geoip / 其余未接线防御与统计）；完整 extra-info（dirreq/exit/hidserv 与真网归档） |
| **洋葱托管** | 无（未上线） | ESTABLISH_INTRO；ntor `rend_circ_nonce`；BEGIN_DIR 上传；type-8 致盲证书 + 双层加密密封；torrc `HiddenService*` | **真网发布后被客户端找到并完成 INTRODUCE2→RENDEZVOUS**；官方 intro/rend 生命周期与限速；vanguards |
| **网桥 / PT** | 无 | `pkg/pt` 子进程框架、obfs4 配置解析、本地 integration 桩 | 向 BridgeAuth 生产发布；客户端经官方 PT 进网；网桥描述符/统计与 C Tor 对齐 |
| **控制端口** | AUTHENTICATE；**AUTHCHALLENGE SAFECOOKIE**；COOKIE / HASHEDPASSWORD；GETINFO/GETCONF/SETCONF 子集；**GETINFO version 与 PROTOCOLINFO VERSION 对齐 `0.4.9.11 (gotor)`**；**GETINFO traffic/read 与 traffic/written 为入口 OR TLS 累计字节**；SETEVENTS（CIRC/STREAM/BW/NOTICE 等）；SIGNAL；MAPADDRESS | GETINFO 键远少于 control-spec | ADD_ONION / DEL_ONION；EXTENDCIRCUIT / ATTACHSTREAM；HSFETCH / HSPOST；USEFEATURE；完整 `circuit-status` / `ns/id` / `desc/id` 等 |

近期：**G123**（TLS 会话恢复绕过证书校验）已用 `VerifyConnection` 修好，见 `pkg/connection/connection.go`（2026-08，`2612779`）。客户端 Link 身份校验仍以 CERTS 为准，不把 TLS 成功当成身份成功。

### 实验中继现状（2026-08-19）

实验中继：权威已收描述符，投票可见 **Valid / V2Dir**，**缺 Running**，**未进共识**。入站握手、本端 self-test、中间跳出站握手已有实现；self-test 成功 ≠ 权威 Running；协议可被 EXTEND ≠ 已在真网当中间跳。ORPort 通 ≠ 上线。

---

## 共识协议门槛（2026-02 / 2026-07 共识，C Tor 0.4.9.11 时期）

权威写入共识的列表（[subprotocol-versioning](https://spec.torproject.org/tor-spec/subprotocol-versioning.html)）：

```
recommended-client-protocols  Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
required-client-protocols     Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
recommended-relay-protocols   Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-relay-protocols      Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
```

**客户端**：gotor 主路径已覆盖 recommended-client-protocols（含 HS 客户端 HSDir/HSIntro/HSRend），并额外实现了尚未 required 的 Relay=5/6、Conflux、Padding=2。HS 电路已接客户端 vanguards（固定 L2+L3，读共识 `guard-hs-l*`）。洋葱 PoW 客户端已接线（无真网 PoW 服务验收）。仍缺托管侧 vanguards 与 PT 生产，不是主握手。

**中继上线硬门槛不只是 ORPort 通。** 权威要看到：

1. 描述符 `proto` **诚实宣告且真正实现** `required-relay-protocols`：尤其 **DirCache=2、HSDir=2、HSIntro=4-5、HSRend=2、LinkAuth=3**。
2. Self-test 成功 → 投票 **Running**（再谈 Guard/Exit/HSDir/V2Dir 等旗标）。
3. 可被其他中继 EXTEND 进来当中间跳。

当前描述符写的是：

```
proto Cons=2 Desc=2 FlowCtrl=1-2 Link=3-5 LinkAuth=3 Microdesc=2 Relay=2-4
```

问题：缺 **DirCache=2 / HSDir / HSIntro / HSRend**（代码已有切片，缺真网被当缓存 / 被选 / extra-info hidserv，**禁止**写进 `proto`）；仍发 Link 3。**禁止**在未实现时把 required 行写进 `proto` 骗权威。

---

## 给后续实现的清单（按优先级）

做完一项：改本文件状态 + `IMPLEMENTATION_STATUS.md`，写真网路径 / 权威投票 / 是否进共识（不要写真实主机、地址或指纹）。一个 PR 只做一项。

### 1. 中继进共识（Running / self-test）

- [ ] **状态**：PARTIAL（入站握手已修：VERSIONS 后 CERTS type 1/2/4/5/7 + AUTH_CHALLENGE + NETINFO，CircID 协商后切 4 字节。self-test 已接到发布门闩：未成功且未 `AssumeReachable` 则不 POST；成功经已有客户端电路 EXTEND2 到本 ORPort。描述符 `proto` 只宣告已实现的 Cons/Desc/Microdesc/Link/LinkAuth/Relay/FlowCtrl。实验中继仍仅 Valid/V2Dir，**缺真网 Running**，未进共识）
- **现有代码**：`pkg/relay/selftest.go`、`pkg/client/selftest.go`、`pkg/relay/or_handler.go`、`pkg/relay/or_certs.go`、`pkg/relay/descriptor.go`、`pkg/relay/publisher.go`、`pkg/relay/server.go`（`startPublisher`）、`pkg/relay/descriptor_verify.go`
- **已做（协议切片，2026-09-19）**：去掉非现行名 `Circuit=`、未实现的中继侧 `Padding=2`/`Conflux=1`、以及 TAP 时代的 `Relay=1`。补上已实现的 `Cons=2` `Desc=2` `Microdesc=2`；`Relay=2-4`。仍禁止 `DirCache=2` / HS* / `Relay=5-6`。
- **要做**：观察权威投票是否出现 `Running` 并进入共识 `r` 行。self-test 成功或权威 200 **仍不等于** Running。
- **禁止**：把权威 200、Valid 或本端 self-test 成功写成「已进共识」；伪造 Running；全零 identity / ntor key。

### 2. 真网当中间跳

- [ ] **状态**：PARTIAL（出站握手 / CircID MSB / 按身份入池 / 剥层与回程已接线并有离线单测；**无**「官方客户端经 gotor middle 出网」证据）
- **现有代码**：`pkg/relay/extension.go`、`pkg/relay/forwarding.go`、`pkg/relay/forwarding_extend.go`、`pkg/relay/circuit_handler.go`、`pkg/relay/or_listener.go`、`pkg/relay/middlehop_test.go`
- **已做（协议切片，2026-08-20）**：出站复用 `protocol.Handshake`（VERSIONS→CERTS→NETINFO，跳过 AUTH_CHALLENGE）；link v4+ 出站 CircID 置 MSB；EXTEND2 type 2/3 身份 + `RequireCERTS`；连接池按地址+身份；下一跳 DESTROY 拆除入站电路。成功条件是这些可测行为，不是真网 Running / 已被选中。
- **要做（观察/运维验收）**：官方客户端建 3-hop 且 middle 为本中继。此项剩余主要是权威 Running 与可达性，不是再改官方键语义。
- **禁止**：只用 mocknet / 本地两进程互连宣称 WORKING；把出站握手单测写成「已在真网当中间跳」；Ed25519 误当经典 ntor NODEID；公开材料写主机、IP、指纹。

### 3. DirCache 对外服务

- [ ] **状态**：PARTIAL（客户端 **拉** consdiff 已对齐；中继可 BEGIN_DIR / 明文 DirPort 提供 **ns（`cached-consensus`）与 microdesc（`cached-microdesc-consensus`）分库**、micro/all、`/tor/keys/fp`、`/tor/keys/all`、**最多 72 小时历史→当前 limited-ed**、**gzip/deflate/`.z`**、**If-Modified-Since 304**、**FPRLIST 过滤权威签名（未过半 404）**、**x-zstd / x-tor-lzma**、**预压缩 consdiff 库**。未宣告 DirCache=2；**无**官方客户端把本中继当缓存的证据）
- **现有代码**：客户端 `pkg/directory/consdiff.go`、`pkg/directory/consdiff_gen.go`、`pkg/directory/consdiff_lib.go`、`pkg/directory/dircompress.go`、`pkg/directory/fprlist.go`、`pkg/directory/directory.go`、`pkg/directory/authcert.go`、`pkg/directory/flavor.go`、`pkg/directory/consensus_disk.go`、`pkg/directory/consensus_ns.go`、`pkg/directory/consensus_hist.go`（hist + `.prev`，按 flavor 分库）。中继 `pkg/relay/dirport.go`、`pkg/relay/server.go`（`DirCache` / `DirPort` 接线）、描述符 `DirPort` 字段（`pkg/relay/descriptor.go`）。互操作 `docs/interop/dircache-consdiff.md`。
- **已做（协议切片，2026-08-20）**：`GenerateConsensusDiff` 产出 limited-ed；换共识保留 `.prev`；匹配摘要则回 diff，否则整份；`/diff/` 未知 404。**#67**：`Accept-Encoding: gzip|deflate`、路径 `.z` 走 zlib、`If-Modified-Since`→304（共识 `Last-Modified` 用 `valid-after`）。**#71**：`/consensus/<FPRLIST>` 与 `/diff/<HASH>/<FPRLIST>` 按身份前缀筛 `directory-signature`，须超过半数被请求权威已签名否则 404；`all` / 无列表回全部签名。**#73**：协商优先 `x-tor-lzma` → `x-zstd` → gzip → deflate；lzma 为 LZMA Alone（preset ≤ 6），只缓存整份共识 / limited-ed；FPRLIST 过滤体与其它文档退回 zstd/gzip。**#75**：`cached-microdesc-consensus.hist/<FromDigest>` 保留最多 72 小时 / 72 份；落后两期以上也可 limited-ed；文件名必须等于正文 FromDigest；过期回整份或 `/diff/` 404；FPRLIST 不实时 LCS。描述符 proto **禁止** `DirCache=`。
- **已做（协议切片，2026-09-19）**：ns 与 microdesc **分库**。`/consensus-microdesc*` 只读 `cached-microdesc-consensus`；`/consensus*` 只读 `cached-consensus`；文件 flavor 与路径不符则 404。中继 DirCache 在 microdesc 共识之后另拉并验签 ns 共识，**不**写入选路 `lastConsensusRaw`。ns 同样 72h hist；consdiff 缓存键带 flavor。**仍禁止** `DirCache=`。
- **已做（协议切片，2026-09-19）**：预压缩 consdiff 库。换共识时按 hist/.prev 预计算 limited-ed，落盘 `cached-*-consensus.diff/<FromDigest>{,.lzma,.zst,.gz,.z}`；DirPort 优先出库，未命中再实时 LCS。FPRLIST 仍不走预计算。**仍禁止** `DirCache=`。
- **要做（未达 DirCache=2）**：真网被官方客户端当缓存。在此之前 **禁止** 在 `proto` 写 `DirCache=2`。
- **禁止**：只开 DirPort 回 200 空体；宣告 `DirCache=2` 却只会整份或空 diff；用明文 DirPort 拉 HS 描述符并宣称安全。

### 4. HSDir / intro / rend 中继角色

- [ ] **状态**：PARTIAL（末端跳 ESTABLISH + **INTRODUCE1 转发 INTRODUCE2 / ACK** + **引言点 DOS_PARAMS / 共识 HiddenServiceEnableIntroDoS\* 令牌桶** + **RENDEZVOUS1 会合并拼电路** + **会合点仅末跳 / 未会合 10min TTL** + **HSDir `/tor/hs/3` 验签收/服 + 哈希环 spread_store 责任**。未宣告 HS*。**无**真网被选为 intro/rend/HSDir 证据）
- **现有代码**：客户端 `pkg/onion/onion.go`、`pkg/onion/hsdir_index.go`、`pkg/onion/begindir.go`、`pkg/onion/establish_intro.go`、`pkg/onion/hsdir_match.go`。中继 `pkg/relay/hsintro.go`、`pkg/relay/hsrend.go`、`pkg/relay/hsdir.go`、`pkg/relay/forwarding.go`、`pkg/relay/circuit_handler.go`。互操作 `docs/interop/hs-intro-rend.md`。
- **已做（协议切片，2026-08-20，#69；哈希环 / 引言限速 / 会合生命周期 2026-09-19）**：INTRODUCE1 按 AUTH_KEY 转发；RENDEZVOUS1 cookie 一次性取出后发 RENDEZVOUS2 并拼接。**会合点**：C Tor `n_chan` 语义（已 EXTEND2 则 DESTROY）；未会合 cookie 10 分钟 TTL（TIMEOUT）与最多 128 等待；内存计数 `HSStats`（不写 extra-info `hidserv-*`）。**哈希环**：读共识 `hsdir_n_replicas` / `hsdir_spread_fetch` / `hsdir_spread_store`；上传用 spread_store；DirCache 在环就绪后拒绝非责任节点的 POST（404）。**引言点限速**：解析 ESTABLISH_INTRO `DOS_PARAMS`（覆盖共识）；否则读 `HiddenServiceEnableIntroDoSDefense`（默认关）/ `RatePerSec=25` / `BurstPerSec=200`；桶空时 ACK `NOT_RECOGNIZED`（对齐 C Tor UNKNOWN_ID），不转发 INTRODUCE2。描述符 proto **禁止** `HSDir=` / `HSIntro=` / `HSRend=`。
- **要做（未达 HS* proto）**：extra-info `hidserv-*` 统计；真网被选。在此之前 **禁止** 在 `proto` 写 HS*。
- **禁止**：描述符写上 HSDir/HSIntro/HSRend 但收到 cell 就 DESTROY；用电路 ntor 冒充 hs-ntor；把离线单测写成「已具备完整 HS 中继角色」。

### 5. LinkAuth=3 服务端

- [ ] **状态**：PARTIAL（应答方已校验 AUTHENTICATE AuthType 3：SLOG/CLOG/SCERT/TLSSECRETS/SIG；描述符已宣告 `LinkAuth=3`。AUTH_CHALLENGE 只广告方法 3，AuthType 1 拒绝。普通客户端仍可不认证。**无**真网权威/中继作为发起方完成认证的观察证据）
- **现有代码**：`pkg/relay/or_auth.go`、`pkg/relay/or_handler.go`、`pkg/relay/or_certs.go`（type 6）。互操作 `docs/interop/linkauth3.md`。
- **已做（协议切片，2026-08-20）**：抄本截到 AUTH_CHALLENGE / AUTH 之前；CERTS type 2/4/6/7 + AUTH0003 字段与 Ed25519 SIG；TLS exporter context=CID。伪造 AUTH 则握手失败。
- **已做（协议切片，2026-09-19）**：AUTH_CHALLENGE 只广告方法 3；未实现的 AuthType 1 不列入 N_METHODS，收到仍拒绝。
- **要做**：真网中继互连观察。不要把 TLS 客户端证书当成 LinkAuth。
- **禁止**：宣告 `LinkAuth=3` 却跳过 AUTHENTICATE；无 TLS exporter 时接受伪造 AUTH。

### 6. relay 侧 CGO

- [ ] **状态**：PARTIAL（服务端识别 ntor-v3 type 3 `[02 06]`，KDF 160，AES-128 ENC_UIV + v1 剥层/回程；出口 DATA 按 488 分片；**出口电路级 SENDME v1 FIFO**；**FlowCtrl=2 出口 TOR_VEGAS（`cwnd-inflight` + orconn_blocked）**。描述符仍 `Relay=2-4`。**无**真网被请求 CGO 的观察；无中继出口真网 soak）
- **现有代码**：客户端 `pkg/crypto/cgo.go`、`pkg/circuit` CGO 路径；中继 `pkg/relay/circuit_crypto.go`、`pkg/crypto/ntorv3_server.go`。互操作 `docs/interop/cgo-relay.md`。
- **已做（协议切片，2026-08-20）**：畸形 type 3 失败握手；末端 `RelayForward` + `RelayOriginate`；中间跳 peel + `wrapOutbound`（不误 originate）。**禁止** `Relay=5-6`。
- **已做（协议切片，2026-09-19）**：入向 DATA 凑满 increment 后发电路级 SENDME v1，tag 为 20 字节 tor1 digest 或 16 字节 CGO T；出口发出 DATA 后 FIFO 记下 tag，客户端电路级 SENDME 必须 v1 且匹配，否则 DESTROY TORPROTOCOL。CGO 电路不发流级 SENDME。
- **已做（协议切片，2026-09-19）**：出口 FlowCtrl=2 接到 `circuit.Vegas`：发出 DATA 记 `inflight`，电路级 SENDME 跑 Slow Start / 拥塞避免，额度是 `cwnd-inflight`。共识 `cc_*` 经 `SetCCParamsFromConsensus` 注入。BEGIN 不得覆盖已有 Vegas。CC 电路不看流级窗口。
- **已做（协议切片，2026-09-19）**：出口采样 orconn_blocked：向客户端写出排队 >1，或单次 Encode ≥100ms（只报一次）。SENDME 前写入 `vegas.blockedChan`，对齐客户端 `Connection.WriteBlocked()`。无中继出口真网 soak。
- **要做**：真网被官方客户端请求 CGO 的证据；中继出口真网 soak。在此之前 **禁止** 在 `proto` 写 `Relay=5-6`。
- **禁止**：AES-256 当 CGO；未协商偷偷用 tor1 还宣称 CGO；`CGO_AES_BITS` 与 C Tor 不一致。

### 7. 洋葱托管真网 INTRODUCE2

- [ ] **状态**：PARTIAL（本地解析/密封；**未上线**）
- **现有代码**：`pkg/onion/service.go`、`pkg/onion/introduce2.go`、`pkg/onion/hsdesc_seal.go`、`pkg/onion/establish_intro.go`、`pkg/onion/rendezvous1.go`、`pkg/onion/begindir.go`
- **要做**：真网 ESTABLISH_INTRO → 描述符上 HSDir → 官方/gotor 客户端访问 → INTRODUCE2 解密 → RENDEZVOUS1 → BEGIN/DATA。写清 onion 地址与 HTTP 状态。
- **禁止**：`TestHandleIntroduce2` 的 mock 字节当 WORKING；明文上传描述符；全零 intro/ntor key。

### 8. extra-info 完整

- [ ] **状态**：PARTIAL（digest 交叉引用 + 观测带宽历史已接线，含出站中间跳 OR；**conn-bi-direct / ipv6-conn-bi-direct 满 24h 才写**；**dirreq-v3-resp / dirreq-v3-ips / dirreq-v3-reqs / dirreq-v3-direct-dl / dirreq-v3-tunneled-dl 满 24h 才写**；ips/reqs 仅 `??`；**exit-* 满 24h 且有出口 TCP 才写**；**无** dl 分位数、hidserv，**无**真网权威归档观察）
- **现有代码**：`GenerateDescriptorPair`（`pkg/relay/descriptor.go`）、`BandwidthHistory`（`pkg/relay/bw_history.go`）、`PublishDescriptorPair`（`pkg/relay/publisher.go`）。互操作 `docs/interop/extra-info.md`。
- **已做（协议切片，2026-08-20）**：先签 extra-info 再写 `extra-info-digest` SHA-1 hex + SHA-256 无填充 base64；`published` 同一时刻；router+extra-info 一次 POST。900s 已完成格才写 write/read-history；`BWHistory*` 最后一值是未完成桶。无观测不写 history。
- **已做（协议切片，2026-09-19）**：EXTEND 出站中间跳 OR 在 TLS 之下与入站共用 `BandwidthHistory`（`connection.Config.WrapConn`）。出口流 TCP 不计入。无观测仍不写 history。
- **已做（协议切片，2026-09-19）**：`conn-bi-direct` 按 C Tor 10s / 20480 / 10× 分类入站与出站中间跳 OR；满 24h 且该窗有分类才写入 extra-info。
- **已做（协议切片，2026-09-19）**：`ipv6-conn-bi-direct` 对同一窗的 IPv6 OR 分计（IPv4-mapped 不算）；无 IPv6 分类不写。
- **已做（协议切片，2026-09-19）**：`dirreq-stats-end` / `dirreq-v3-resp` 统计 ns/microdesc 的 200/304/404 等；满 24h 且有计数才写；向上取 4。无 geoip，不写 ips/reqs。
- **已做（协议切片，2026-09-19）**：`dirreq-v3-direct-dl` / `dirreq-v3-tunneled-dl` 仅写 `complete`（DirPort HTTP vs BEGIN_DIR 200）；满 24h 且该通道有完成才写。无时长/速率观测，不写 timeout/running/分位数。
- **已做（协议切片，2026-09-19）**：`dirreq-v3-ips` / `dirreq-v3-reqs` 无 geoip 一律 `??=N`（unique IP / 请求次数，向上取 8）。DirPort 用 TCP 对端，BEGIN_DIR 用相邻 OR。不写国家码。
- **已做（协议切片，2026-09-19）**：`exit-stats-end` / `exit-kibibytes-written` / `exit-kibibytes-read` / `exit-streams-opened` 统计成功 RELAY_BEGIN 的出口 TCP；interesting ports 分列，其余 other；KiB 向上取整、流数向上取 4。BEGIN_DIR 不计。非出口不写。
- **要做**：geoip 国家码、dl 分位数、hidserv（需 24h 观测与混淆）；真网权威归档。不要把空统计当完整。
- **禁止**：空 extra-info 当「已实现完整」；编造未观测的带宽数字。

### 9. 官方级 DoS

- [ ] **状态**：PARTIAL（官方 `DoS*` 键 + CREATE2/每 IP + **auto 跟共识** + **ConnectRate/Burst** + **StreamCreation** + **AUTHENTICATE 单跳区分** + **CircuitCreationDefenseType** + **共识 nodelist 核对身份**）
- **现有代码**：`DoSGuard`（`pkg/relay/dos.go`）接到 OR 监听与 `handleCreate2`。`ProtectionManager` 仍未接入，不要当官方 DoS。互操作 `docs/interop/dos-relay.md`。
- **已做（协议切片，2026-08-20）**：解析 `DoSCircuitCreation*` / `DoSConnectionEnabled` / `MaxConcurrentCount` / `DoSRefuseSingleHopClient`；默认 auto 且无共识则关。显式 1 时每 IP 并发 OR 上限 + CREATE2 令牌桶（达 MinConnections 后）；桶空进入 DefenseTimePeriod。`RefuseSingleHop`：仅成功 EXTEND（下一跳已登记）后才放行 BEGIN/BEGIN_DIR/RESOLVE。**不改** `ConnLimit` 语义。
- **已做（协议切片，2026-09-19）**：`Enabled=auto` 读共识 `DoSCircuitCreationEnabled` / `DoSConnectionEnabled`（0–1，缺省 0）；显式 0/1 不被覆盖。`DoSConnectionConnectRate` / `Burst` / `ConnectDefenseTimePeriod`：torrc 0 跟共识（缺省 20/40/24h，夹紧 1…INT32_MAX / 防御窗最少 10s）。bootstrap 后 `SetDoSConsensusParams`。
- **已做（协议切片，2026-09-19）**：`DoSStreamCreationEnabled` auto 跟共识；每电路 BEGIN/BEGIN_DIR/RESOLVE 令牌桶（缺省 100/300）；`DefenseType` 1=无动作、2=`RELAY_END` MISC、3=`DESTROY` RESOURCELIMIT（缺省 2）。
- **已做（协议切片，2026-09-19）**：`DoSRefuseSingleHopClient`：未成功 EXTEND 的普通客户端 DESTROY；入站已 AUTHENTICATE（LinkAuth=3）且共识 nodelist 收录该 RSA/Ed25519 身份的中继单跳放行。尚未注入共识时 fail-open。BEGIN 时再查，以便晚到的共识仍生效。
- **已做（协议切片，2026-09-19）**：`DoSCircuitCreationDefenseType`：torrc 0 跟共识（缺省 2）；1=桶空仍放行、不进防御窗；2=拒绝 CREATE2 并进入 DefenseTimePeriod。显式 1/2 不被共识覆盖。
- **要做**：不宣称完整 dos.c（无 geoip、无其余未接线防御/统计）。
- **禁止**：只加全局 `MaxConnections` 就写「官方级 DoS」；用审计文档里的「100% DoS」自评；默认 auto 却按已开启宣传；宣称已对齐完整 dos.c。

### 10. vanguards

- [ ] **状态**：PARTIAL（客户端 HS 电路固定 L2+L3 并落盘；读共识 `guard-hs-l2-*` / `guard-hs-l3-*`；**无**托管侧）
- **现有代码**：`pkg/path/vanguards.go`；`pkg/onion/hs_path.go`（`CircuitAdapter` / `BegindirFetcher` / SOCKS）；`pkg/circuit/builder.go`（`Path.Middle2`）。互操作 `docs/interop/vanguards-lite.md`。
- **已做（协议切片，2026-08-20，#65）**：L2 默认 4、寿命 1–12 天；`DataDirectory/state` 自有键 `GotorHSLayer2Guards`（不改官方 Guard 行）；L1 优先持久入口；已注入则失败关闭；目标碰巧是 L2 时只本条避开；升为入口的节点退出 L2；三跳拒绝同家族；`AvoidDiskWrites` 不落盘。
- **已做（协议切片，2026-09-19）**：L3 默认 8、寿命 1–48 小时 max(X,X)；HS 电路 L1→L2→L3→目标；`GotorHSLayer3Guards` 落盘；L1/L2/L3 互斥；Builder 对 `Middle2` 多 EXTEND2。SOCKS 仍三跳。
- **已做（协议切片，2026-09-19）**：`VanguardParamsFromConsensus` 读 `guard-hs-l2-*` / `guard-hs-l3-*`；数量夹紧 1–19 / 1–20；寿命秒；min>max 回退默认。拉共识后 `ApplyConsensusParams`，下一轮选路补员或裁剪。
- **要做**：托管侧 intro/rend 固定 L2/L3。
- **禁止**：随机多跳冒充 vanguards；无持久化状态就宣称已防护；把本切片写成含托管侧的完整 vanguards 插件。

### 11. Bridge / PT 生产路径

- [ ] **状态**：PARTIAL（框架，非验收范围）
- **现有代码**：`pkg/pt/`（`manager.go`、`client.go`、`server.go`、`obfs4/`）、`pkg/relay/bridgedb.go`、`pkg/relay/publisher.go`（默认仍偏桥权威 URL）
- **要做**：客户端 `UseBridges` + 外部 lyrebird/obfs4proxy 进真网；桥模式发布到 BridgeAuth；控制口 `GETINFO` 桥状态。先完成中继进共识再投入产 PT。
- **禁止**：本地 `TestBridge` integration 或 mock PT 当生产；内置不完整 obfs4 宣称可抗审查。

### 12. 洋葱客户端 PoW

- [ ] **状态**：PARTIAL（解析 `pow-params v1` + 纯 Go HashX/Equi-X + INTRODUCE1 内层 EXT 0x02；**无**真网开启 PoW 的洋葱服务验收；**无**托管侧验证）
- **现有代码**：`pkg/crypto/hashx/`、`pkg/crypto/equix/`、`pkg/onion/pow.go`（`ConnectToOnionService` / `parseDecryptedLayer`）。互操作 `docs/interop/hs-pow.md`。
- **已做（协议切片，2026-09-19）**：对照 HashX / C Tor Equi-X 公开向量；挑战 `P||ID||C||N||htonl(E)`；Blake2b-32 工作量 `R*E` 不溢出 uint32；`suggested-effort=0` 不解；过期种子失败。描述符 proto **禁止**因此写 HS*。
- **要做**：真网 PoW 服务 INTRODUCE 被接受；托管侧验证与 prop 362 控制环（P2，托管未上线前不做）。
- **禁止**：把无 PoW 的 `.onion` HTTP 200 写成 PoW WORKING；链接 LGPL Equi-X C / CGO；托管未上线却宣称 HiddenServicePoW。

---

## Arti 新特性追踪

给后续实现：先看「是否该跟」，再看 Arti/C Tor 状态。版本号均来自官方 CHANGELOG / 博文 / issue，**未查到就写未查到，禁止编造落地版本**。

| 特性 / proposal | Arti 状态 | C Tor 是否已有 | gotor | 现有代码路径 | 是否该跟 |
|-----------------|-----------|----------------|-------|--------------|----------|
| **CGO / Relay=5–6**（[prop 359](https://spec.torproject.org/proposals/359-cgo-redux.html)） | 1.4.6 开始 `tor-proto` 协商（「尚不可用」）；1.5.0 实验协商；**2.5.0 标 stable 并进 `full` 构建**；**2.6.0 始终启用**（去掉 `counter-galois-onion` cargo feature）。洋葱电路上的 CGO 在 2.5.1 仍实验 | 有（0.4.9 mainnet 已与 gotor 客户端互操作） | 客户端 **WORKING**；中继 **PARTIAL**（可协商剥层，未宣告 Relay=5-6） | `pkg/crypto/cgo.go`、`pkg/circuit`、`pkg/relay/circuit_crypto.go` | **P1** 客户端已跟；中继协议切片已接线，缺真网被请求证据。HS-CGO 实验开关 **P2** |
| **Conflux**（[prop 329](https://spec.torproject.org/proposals/329-traffic-splitting.html)） | 1.5.0 实验后端（changelog 写「尚未使用」）；1.4.6+ 测试与 reactor 重构；2.0.0 `relay-conflux.md` 设计。**截至 2.5.x 博文未宣布 conflux 已 stable** | 有（0.4.8.4 起，exit 多电路；洋葱当时未支持） | 客户端 **WORKING**（真网 LINK + `IsTor=true`） | `pkg/cell/conflux.go`、`pkg/circuit/conflux.go`、`pkg/path/conflux.go` | **P1**（mainnet 已宣告且 C Tor 在用）。不要为对齐 Arti 未 stable 的 reactor 改 wire |
| **ntor-v3** | **1.4.3 起始终启用**（去掉 `ntor_v3` feature，[!2907](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2907)） | 有（现行默认） | **WORKING**（默认 HTYPE 0x0003） | `pkg/crypto/ntorv3.go`、`pkg/circuit/extension.go` | **P0**（recommended Relay=4 / 现网默认） |
| **洋葱 PoW / 反 DoS**（[prop 327](https://spec.torproject.org/proposals/327-pow-over-intro.html)、[prop 362](https://spec.torproject.org/proposals/362-update-pow-control-loop.html)） | 1.3.x 设计/铺地；1.4.6 换成 prop 362 控制环；1.5.0 实验支持（[!3106](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3106)）。稳定化仍开放：[arti#1751](https://gitlab.torproject.org/tpo/core/arti/-/issues/1751) | 有（0.4.8 `HiddenServicePoW*`，默认关） | **PARTIAL**（客户端） | `pkg/crypto/hashx`、`pkg/crypto/equix`、`pkg/onion/pow.go` | **P1** 客户端切片已接线。真网 PoW 服务验收仍缺。**P2** 托管：gotor 托管未上线前不要做。未 required |
| **Vanguards-lite** | **1.2.2 默认** lite（[#1272](https://gitlab.torproject.org/tpo/core/arti/-/issues/1272) 等）；1.2.3 修 TROVE-2024-003 / [arti#1409](https://gitlab.torproject.org/tpo/core/arti/-/issues/1409)（电路少一跳） | 有（默认 lite；完整 L3 为插件/完整 vanguards） | **PARTIAL**（客户端固定 L2+L3 且读共识 `guard-hs-l*`；无托管侧） | `pkg/path/vanguards.go`、`pkg/onion/hs_path.go` | **P1** 客户端 L3 与共识参数已接线。托管侧仍缺。见上文清单第 10 项 |
| **RPC / 嵌入 API** | RPC **1.4.2 稳定**；2.1.0/2.2.0 非阻塞与 superuser；2.0.0 `inet-auto`。嵌入库自 1.0.0 起是 `arti-client`（2.0.0 起 `arti` crate API 标 experimental） | 无 RPC；用 control-spec | RPC **MISSING**；Go 库嵌入 **PARTIAL**（`pkg/client`）；控制口子集 **WORKING** | `pkg/client`、`pkg/control` | **P2**。保持 C Tor 控制口 + Go API；不要为追 Arti RPC 破坏现有控制器 |
| **arti-relay 中继工作** | 2.0.0 TLS 服务端 / `ChanMgr` / reactor；2.2.0 入向 TLS+认证；1.9.0 入向 DATA、初始化 guard/circ/dir；2.5.1 入向消息、BeginDir/Resolve、未完成 DirMirror、描述符上传（[#2549](https://gitlab.torproject.org/tpo/core/arti/-/issues/2549)）。**未宣布可跑生产中继** | 完整中继 | **PARTIAL**（实验，未进共识） | `pkg/relay/*` | **P1** 跟共识硬门槛（Running、DirCache/HS*/LinkAuth），不是复制 Arti 未完成内部件 |
| **目录 / consensus / protover** | 1.4.3 缺协议则退出（[!2929](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2929)）；`MicroDesc` 更名为 `Microdesc`。1.5.0 `tor-netdoc` API 大改。2.2.0 consdiff **生成**后端；2.5.0 编解码 router/microdesc/consensus；2.5.1 开始算共识；2.6.0 可算 microdesc、Extra Info 雏形、`DirMgr` 作 `DirServer` 后端 | 权威+缓存完整；客户端 consdiff=DirCache=2 | 客户端 **WORKING**；对外缓存 **PARTIAL**（**ns/microdesc 分库** + 最多 72h 历史→当前 limited-ed + gzip/304 + FPRLIST + x-zstd/x-tor-lzma + 预压缩 consdiff 库；未宣告 DirCache=2） | `pkg/directory/`、`pkg/relay/dirport.go` | 客户端 **P0 已跟**。新投票/共识格式：**P2**，等共识行要求。中继对外 DirCache：**P1**（required-relay；未达完整前禁止写 proto） |
| **FlowCtrl=2 / 拥塞控制**（[prop 324](https://spec.torproject.org/proposals/324-rtt-congestion-control.html)） | 1.4.3 握手铺地；1.5.0 实验；1.4.6 XON/XOFF；**2.4.0 标 stable**（`flowctl-cc`）；**2.5.0 默认构建启用**；**2.6.0 始终启用**（去掉 `flowctl-cc` feature）。2.5.1 修 XON 把 Bps 当成 bps 的 8 倍限速 bug | 有（现网默认 Vegas） | 客户端 **WORKING** | `pkg/circuit/vegas.go`、`pkg/circuit/ccparams.go` | **P0**（recommended FlowCtrl=1-2）。HS 上协商仍是 Arti 实验 → **P2** |
| **HTTP CONNECT 代理**（[prop 365](https://spec.torproject.org/proposals/365-http-connect-ext.html)） | 1.7.0 实验 `http-connect`；**2.2.0 稳定且默认开** | 有（`HTTPTunnelPort`） | **PARTIAL**（有端口，非 Arti 扩展全集） | `pkg/httptunnel/httptunnel.go` | **P1** 对齐 C Tor `HTTPTunnelPort` 即可；Arti 扩展头 **P2** |
| **电路填充** | 1.6.0 实验 **maybenot**（`circ-padding-manual`）；1.7.0 第一跳按 channel 聚合。与 C Tor 直方图机不是同一实现 | 有（Padding=2 机器） | 客户端 **WORKING**（C Tor 风格协商+直方图，真网 ACK） | `pkg/circuit/circpad.go` | **P1 已跟 C Tor 机**。不要换成 Arti maybenot 实验机还宣称 Padding=2 |
| **HS 电路 CGO/CC**（2.5.1 新） | 2.5.1 实验 feature，博文写「希望很快 stable」 | 未查到 0.4.9.11 已把 HS-CGO 标 required | **MISSING** | 无 | **P2**。等官方 required 或 mainnet 双方默认，再动洋葱电路加密 |

---

## 如何更新「Arti 新特性追踪」

1. 打开现行 [Arti CHANGELOG.md](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CHANGELOG.md)（以及同期 [Tor Blog / Arti](https://blog.torproject.org/category/arti/)）。只收录**影响互操作**的项（wire、protover、握手、目录格式、HS 单元格），跳过 MSRV、CI、纯 API 重命名。
2. 对照最新共识里的 `recommended-client-protocols` / `required-relay-protocols` 等四行（CollecTor 或权威文档）。**该跟**列按下面改，不要按「Arti 刚合并」升级优先级：
   - **P0**：共识 recommended/required 已列出，或现网默认握手（如 ntor-v3）。
   - **P1**：mainnet 已宣告，且 C Tor 与 Arti **都在用**（或一边生产、一边明确互操作）。
   - **P2**：仅 Arti 实验 feature、或「仍在做」的中继/权威内部工作。
3. 填表：Arti 写**已落地版本或 tracking issue URL**；查不到写「未查到」，禁止猜版本号。
4. 改 gotor 列时同步改上文清单与 `IMPLEMENTATION_STATUS.md`。禁止把 mock、全零 key、功能分支未合入代码写成 WORKING。
5. 更新日期和「对照官方版本」。0.4.8 已 EOL，不要倒退参照。

---

## 实现时怎么用这份文档

1. 先读本节对应项的「现有代码」和「禁止」，再改代码。
2. 协议细节以现行 [tor-spec](https://spec.torproject.org/) / C Tor 0.4.9.11 / Arti 2.5.1 为准，不以过期 ROADMAP、GAPS、AUDIT 自评为准。新特性先看上文「Arti 新特性追踪」的「是否该跟」。
3. 默认 `go test ./...` 不得访问公网。真实验收：`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration`。
4. 互操作字节级说明在 `docs/interop/`；本文件只跟踪**与官方的差距和优先级**。
5. 相关但不替代本文件：[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)（按模块状态）、[`RELAY.md`](RELAY.md)（中继操作）、[`TOR_DROPIN.md`](TOR_DROPIN.md)（CLI/torrc）、[`SECURITY_LIMITATIONS.md`](SECURITY_LIMITATIONS.md)（安全边界）。[`COMPATIBILITY_TESTING.md`](COMPATIBILITY_TESTING.md) 只讲如何跑对照测试，不是差距清单。
