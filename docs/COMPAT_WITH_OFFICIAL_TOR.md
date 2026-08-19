# gotor 与官方 Tor 的兼容差距

**日期**：2026-08-20  
**对照官方版本**：C Tor **0.4.9.11**、Arti **2.5.1**（2026-08-03，[官方博文](https://blog.torproject.org/arti_2_5_1_released/)）  
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

禁止事项对**每一项后续实现**都适用：禁止全零 key fallback、禁止 mock/本地桩当完成、禁止为过测试放松协议校验、禁止 CGO、禁止把「ORPort 通了」写成「已进共识」。
公开 PR / commit **禁止** 写真实服务器名、公网 IP、中继指纹、联系人、内网仓库地址。真网观察用「实验中继」「权威已收描述符」「缺 Running」等不带识别信息的说法。

---

## 声明

gotor **不是** Tor Project 官方实现，也未受其监督或背书。  
**不能当作人身安全级匿名工具。** 需要匿名时请用 [Tor Browser](https://www.torproject.org/download/) 或官方 [Arti](https://gitlab.torproject.org/tpo/core/arti) / [C Tor](https://gitlab.torproject.org/tpo/core/tor)。

---

## 一句话定位

**客户端接近官方推荐协议；中继实验性（描述符可被权威收下，但未进共识、不能当中间跳）；洋葱托管未上线。**

---

## Arti 现行角色（约 2.5.1）

资料：[Arti 2.5.1 博文](https://blog.torproject.org/arti_2_5_1_released/)、[2.5.0 博文](https://blog.torproject.org/arti_2_5_0_released/)、[2.4.0 博文](https://blog.torproject.org/arti_2_4_0_released/)、[CHANGELOG.md](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CHANGELOG.md)（1.0.0–2.2.0 等已收录章节；2.5.x 以博文与 changelog 补丁为准）。

| 角色 | Arti 2.5.1 | 对 gotor 的含义 |
|------|------------|-----------------|
| **客户端** | 可生产：1.0.0（2022-09）起 `arti-client` / SOCKS 即稳定路径；2.5.x 仍在此基础上修性能与安全 | gotor 客户端应对齐 **共识 recommended** 与 Arti/C Tor **都已在 mainnet 用的** 握手，而不是 Arti 实验 cargo feature |
| **洋葱** | **有**：托管自 1.2.0（2024-03）起 `onion-service-service` 非实验；2.5.1 增加 AF_UNIX 后端，HS 上的拥塞控制/CGO 仍是实验 feature（`hsc-negotiate-extensions` / `hss-negotiate-extensions`，[#1948](https://gitlab.torproject.org/tpo/core/arti/-/issues/1948)、[#2473](https://gitlab.torproject.org/tpo/core/arti/-/issues/2473)） | gotor 托管未上线；不要把 Arti 实验 HS-CGO 开关写成「官方已 required」 |
| **中继** | **仍在做**：2.0.0 起电路 reactor / TLS 服务端；2.2.0「更接近可用 middle」；2.5.1 继续（入向消息校验、BeginDir/Resolve、未完成的 `DirMirror`、描述符生成与上传）。**还不能当生产中继**，生产中继仍要 C Tor | gotor 中继同样是实验性；跟 `required-relay-protocols`，不要复制 Arti 未完成的内部类型 |
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
| **客户端** | 共识 9/9 验签、`cached-certs` 重启 0 次 `/tor/keys/fp`、DirCache=2 consdiff、microdesc、Link TLS+CERTS type 7、默认 ntor-v3 CREATE2/EXTEND2、3-hop SOCKS5 `IsTor=true`、RESOLVE、FlowCtrl=2 Vegas soak、Relay=5/6 CGO、Conflux=1、EXTEND2 IPv6、`p`/`p6` 出口策略、Desc=4 family-ids、Padding=2 协商 ACK、v3 `.onion` 客户端 HTTP 200 | Guard 选路与官方指纹仍可能有差异；Fast/MiddleOnly/BadExit 已强制但未单独真网标 WORKING；circpad token-removal | Vanguards-lite；完整 PT/网桥客户端生产路径；与 Tor Browser 同级的隔离/反指纹 |
| **中继** | 描述符可 POST 到权威并获 HTTP 200；交叉证书（onion-key-crosscert / ntor-onion-key-crosscert）与 Ed25519 摘要签名按 dir-spec 生成 | ORPort 监听；CREATE2 经典 ntor / ntor-v3；EXTEND2→CREATE2→EXTENDED2 剥层转发（仅本地/单测）；出口策略解码与 EXIT 流（实验） | **进共识 `Running`**；self-test / 可达性电路；真网当中间跳；对外 DirCache=2（含 consdiff、`/tor/keys`、BEGIN_DIR 完整）；HSDir=2 / HSIntro=4-5 / HSRend=2 中继角色；LinkAuth=3 服务端；relay 侧 CGO；官方级 DoS；完整 extra-info |
| **洋葱托管** | 无（未上线） | ESTABLISH_INTRO；ntor `rend_circ_nonce`；BEGIN_DIR 上传；type-8 致盲证书 + 双层加密密封；torrc `HiddenService*` | **真网发布后被客户端找到并完成 INTRODUCE2→RENDEZVOUS**；官方 intro/rend 生命周期与限速；vanguards |
| **网桥 / PT** | 无 | `pkg/pt` 子进程框架、obfs4 配置解析、本地 integration 桩 | 向 BridgeAuth 生产发布；客户端经官方 PT 进网；网桥描述符/统计与 C Tor 对齐 |
| **控制端口** | AUTHENTICATE；**AUTHCHALLENGE SAFECOOKIE**；COOKIE / HASHEDPASSWORD；GETINFO/GETCONF/SETCONF 子集；SETEVENTS（CIRC/STREAM/BW/NOTICE 等）；SIGNAL；MAPADDRESS | GETINFO 键远少于 control-spec；`version` 仍回 `go-tor 0.1.0`（CLI `--version` 已报 `0.4.9.11 (gotor)`） | ADD_ONION / DEL_ONION；EXTENDCIRCUIT / ATTACHSTREAM；HSFETCH / HSPOST；USEFEATURE；完整 `circuit-status` / `ns/id` / `desc/id` 等 |

近期：**G123**（TLS 会话恢复绕过证书校验）已用 `VerifyConnection` 修好，见 `pkg/connection/connection.go`（2026-08，`2612779`）。客户端 Link 身份校验仍以 CERTS 为准，不把 TLS 成功当成身份成功。

### 实验中继现状（2026-08-19）

实验中继：权威已收描述符，投票可见 **Valid / V2Dir**，**缺 Running**，**未进共识**。ORPort 通 ≠ 上线。

---

## 共识协议门槛（2026-02 / 2026-07 共识，C Tor 0.4.9.11 时期）

权威写入共识的列表（[subprotocol-versioning](https://spec.torproject.org/tor-spec/subprotocol-versioning.html)）：

```
recommended-client-protocols  Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
required-client-protocols     Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
recommended-relay-protocols   Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-relay-protocols      Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
```

**客户端**：gotor 主路径已覆盖 recommended-client-protocols（含 HS 客户端 HSDir/HSIntro/HSRend），并额外实现了尚未 required 的 Relay=5/6、Conflux、Padding=2。缺的是「官方客户端周边」（vanguards、PT 生产），不是主握手。

**中继上线硬门槛不只是 ORPort 通。** 权威要看到：

1. 描述符 `proto` **诚实宣告且真正实现** `required-relay-protocols`：尤其 **DirCache=2、HSDir=2、HSIntro=4-5、HSRend=2、LinkAuth=3**。
2. Self-test 成功 → 投票 **Running**（再谈 Guard/Exit/HSDir/V2Dir 等旗标）。
3. 可被其他中继 EXTEND 进来当中间跳。

当前描述符写的是：

```
proto Link=3-5 Circuit=1-4 Relay=1-4 FlowCtrl=1-2 Padding=2 Conflux=1
```

问题：缺 DirCache/HSDir/HSIntro/HSRend/LinkAuth/Cons/Desc/Microdesc；`Circuit=` 不是现行 proto 名；Link 从 3 起、Conflux=1（mainnet 常见只写 2）。**禁止**在未实现时把 required 行写进 `proto` 骗权威。

---

## 给后续实现的清单（按优先级）

做完一项：改本文件状态 + `IMPLEMENTATION_STATUS.md`，写真网路径 / 权威投票 / 是否进共识（不要写真实主机、地址或指纹）。一个 PR 只做一项。

### 1. 中继进共识（Running / self-test）

- [ ] **状态**：PARTIAL（描述符可上传；实验中继有 Valid/V2Dir、无 Running）
- **现有代码**：`pkg/relay/descriptor.go`、`pkg/relay/publisher.go`、`pkg/relay/server.go`（`startPublisher`）、`pkg/relay/descriptor_verify.go`
- **要做**：对照 C Tor `router.c` / `routerkeys.c` 的 reachability self-test（经电路连回自己的 ORPort）；修复 `proto` 只宣告已实现能力；确认权威投票出现 `Running` 且进入共识 `r` 行。
- **禁止**：把权威 200 或 Valid 写成「已进共识」；伪造 Running；全零 identity / ntor key。

### 2. 真网当中间跳

- [ ] **状态**：PARTIAL（转发代码在；无「官方客户端经 gotor middle 出网」证据）
- **现有代码**：`pkg/relay/circuit_handler.go`、`pkg/relay/extension.go`、`pkg/relay/forwarding.go`、`pkg/relay/forwarding_extend.go`、`pkg/relay/or_listener.go`
- **要做**：被真实 Guard/客户端 EXTEND2 选中；CREATED2 + 剥层转发 + 回程加密；官方 `tor` 建 3-hop 且 middle 为 gotor。
- **禁止**：只用 mocknet / 本地两进程互连宣称 WORKING；Ed25519 误当经典 ntor NODEID。

### 3. DirCache 对外服务

- [ ] **状态**：PARTIAL（客户端 **拉** consdiff 已对齐；中继 **提供** 目录缓存：`main` 上无实现）
- **现有代码**：客户端 `pkg/directory/consdiff.go`、`pkg/directory/directory.go`。中继描述符可写 `DirPort` 字段（`pkg/relay/descriptor.go`）。[`RELAY.md`](RELAY.md) 仍列 DirPort 未完成。**不要**把未合入 `main` 的草稿（例如功能分支上的 `dirport.go`）写成已有路径。
- **要做**：BEGIN_DIR + 可选明文 DirPort；服务 `consensus-microdesc`、microdesc、**consdiff**、`/tor/keys/fp`；通过权威 V2Dir 且被其他客户端当缓存使用。
- **禁止**：只开 DirPort 回 200 空体；宣告 `DirCache=2` 却不会 limited-ed diff；用明文 DirPort 拉 HS 描述符并宣称安全；把未合并草稿当 WORKING。

### 4. HSDir / intro / rend 中继角色

- [ ] **状态**：官方有我们没有（中继侧）。客户端 **用** HSDir/intro/rend 已对齐。
- **现有代码**：客户端 `pkg/onion/onion.go`、`pkg/onion/hsdir_index.go`、`pkg/onion/begindir.go`、`pkg/onion/establish_intro.go`。`pkg/relay` **无** ESTABLISH_INTRO / INTRODUCE / ESTABLISH_RENDEZVOUS 处理。
- **要做**：HSDir=2 收/服务 v3 描述符；HSIntro=4-5 引言点；HSRend=2 会合点。对照 rend-spec-v3 与 C Tor `hs_service.c` / `hs_intropoint.c`。
- **禁止**：描述符写上 HSDir/HSIntro/HSRend 但收到 cell 就 DESTROY；用电路 ntor 冒充 hs-ntor。

### 5. LinkAuth=3 服务端

- [ ] **状态**：官方有我们没有
- **现有代码**：客户端跳过 AUTH_CHALLENGE（符合普通客户端）。服务端 `pkg/relay/or_handler.go` 写明「AUTH_CHALLENGE optional, not implemented yet」。CERTS 发送在 `sendCerts`。
- **要做**：AUTH_CHALLENGE + AUTHENTICATE（Ed25519 LinkAuth=3）；CERTS 含 type 4/5/7 等现行集合。中继互连与权威探测需要这条。
- **禁止**：宣告 `LinkAuth=3` 却不验对端 AUTHENTICATE；把 TLS 客户端证书当成 LinkAuth。

### 6. relay 侧 CGO

- [ ] **状态**：客户端已对齐；中继官方有我们没有
- **现有代码**：客户端 `pkg/crypto/cgo.go`、`pkg/circuit` CGO 路径；官方向量 `pkg/crypto/cgo_test.go`。`pkg/relay` **无** CGO。中继 CREATE2 只做 ntor `0x0002` / ntor-v3 `0x0003`（`circuit_handler.go`）。
- **要做**：服务端识别 Relay=5 `subproto_request` type 3 `[02 06]`，用 AES-128 UIV+ 与 v1 relay message；未协商成功不得回退还宣称 CGO。
- **禁止**：AES-256 当 CGO；未协商偷偷用 tor1；`CGO_AES_BITS` 与 C Tor 不一致。

### 7. 洋葱托管真网 INTRODUCE2

- [ ] **状态**：PARTIAL（本地解析/密封；**未上线**）
- **现有代码**：`pkg/onion/service.go`、`pkg/onion/introduce2.go`、`pkg/onion/hsdesc_seal.go`、`pkg/onion/establish_intro.go`、`pkg/onion/rendezvous1.go`、`pkg/onion/begindir.go`
- **要做**：真网 ESTABLISH_INTRO → 描述符上 HSDir → 官方/gotor 客户端访问 → INTRODUCE2 解密 → RENDEZVOUS1 → BEGIN/DATA。写清 onion 地址与 HTTP 状态。
- **禁止**：`TestHandleIntroduce2` 的 mock 字节当 WORKING；明文上传描述符；全零 intro/ntor key。

### 8. extra-info 完整

- [ ] **状态**：PARTIAL（能签名一份几乎为空的 extra-info）
- **现有代码**：`GenerateExtraInfo`（`pkg/relay/descriptor.go`）、`PublishExtraInfo`（`pkg/relay/publisher.go`）。`Server.startPublisher` 传 `stats=nil`。
- **要做**：dir-spec extra-info：带宽历史、conn-bi-direct、dirreq、exit 统计（若出口）、ed25519+RSA 签名与 server descriptor digest 交叉引用。权威能关联并归档。
- **禁止**：空 extra-info 当「已实现完整」；编造未观测的带宽数字。

### 9. 官方级 DoS

- [ ] **状态**：PARTIAL（有连接/电路计数器，不是 C Tor DoS 子系统）
- **现有代码**：`pkg/relay/protection.go`、`pkg/relay/ratelimit.go`。审计曾指出 CREATE2 路径未完全接入。
- **要做**：对照 C Tor `dos.c` / torrc `DoSCircuitCreation*` `DoSConnection*` `DoSRefuseSingleHopClient` 等：按 IP 的电路创建令牌桶、连接上限、单跳拒绝、共识 `DoS*` 参数。
- **禁止**：只加全局 `MaxConnections` 就写「官方级 DoS」；用审计文档里的「100% DoS」自评。

### 10. vanguards

- [ ] **状态**：官方有我们没有
- **现有代码**：无（`docs/ONION_SERVICE_HOSTING.md` 仅「考虑使用」）。选路在 `pkg/path`、`pkg/onion`。
- **要做**：vanguards-lite（C Tor 默认 / Arti）：HS 电路固定 L2/L3 层，降低 guard discovery。对照 spec 与 C Tor `vanguards_lite`。
- **禁止**：随机多跳冒充 vanguards；无持久化状态就宣称已防护。

### 11. Bridge / PT 生产路径

- [ ] **状态**：PARTIAL（框架，非验收范围）
- **现有代码**：`pkg/pt/`（`manager.go`、`client.go`、`server.go`、`obfs4/`）、`pkg/relay/bridgedb.go`、`pkg/relay/publisher.go`（默认仍偏桥权威 URL）
- **要做**：客户端 `UseBridges` + 外部 lyrebird/obfs4proxy 进真网；桥模式发布到 BridgeAuth；控制口 `GETINFO` 桥状态。先完成中继进共识再投入产 PT。
- **禁止**：本地 `TestBridge` integration 或 mock PT 当生产；内置不完整 obfs4 宣称可抗审查。

---

## Arti 新特性追踪

给后续实现：先看「是否该跟」，再看 Arti/C Tor 状态。版本号均来自官方 CHANGELOG / 博文 / issue，**未查到就写未查到，禁止编造落地版本**。

| 特性 / proposal | Arti 状态 | C Tor 是否已有 | gotor | 现有代码路径 | 是否该跟 |
|-----------------|-----------|----------------|-------|--------------|----------|
| **CGO / Relay=5–6**（[prop 359](https://spec.torproject.org/proposals/359-cgo-redux.html)） | 1.4.6 开始 `tor-proto` 协商（「尚不可用」）；1.5.0 实验协商；**2.5.0 标 stable 并进 `full` 构建**（[博文](https://blog.torproject.org/arti_2_5_0_released/)）。2.5.1 **洋葱电路**上的 CGO 仍实验（`hsc-negotiate-extensions` / `hss-negotiate-extensions`） | 有（0.4.9 mainnet 已与 gotor 客户端互操作） | 客户端 **WORKING**；中继 **MISSING** | `pkg/crypto/cgo.go`、`pkg/circuit`；中继无 | **P1** 客户端已跟；中继等被选为 hop 且对端请求 Relay=6 时再做。HS-CGO 实验开关 **P2** |
| **Conflux**（[prop 329](https://spec.torproject.org/proposals/329-traffic-splitting.html)） | 1.5.0 实验后端（changelog 写「尚未使用」）；1.4.6+ 测试与 reactor 重构；2.0.0 `relay-conflux.md` 设计。**截至 2.5.x 博文未宣布 conflux 已 stable** | 有（0.4.8.4 起，exit 多电路；洋葱当时未支持） | 客户端 **WORKING**（真网 LINK + `IsTor=true`） | `pkg/cell/conflux.go`、`pkg/circuit/conflux.go`、`pkg/path/conflux.go` | **P1**（mainnet 已宣告且 C Tor 在用）。不要为对齐 Arti 未 stable 的 reactor 改 wire |
| **ntor-v3** | **1.4.3 起始终启用**（去掉 `ntor_v3` feature，[!2907](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2907)） | 有（现行默认） | **WORKING**（默认 HTYPE 0x0003） | `pkg/crypto/ntorv3.go`、`pkg/circuit/extension.go` | **P0**（recommended Relay=4 / 现网默认） |
| **洋葱 PoW / 反 DoS**（[prop 327](https://spec.torproject.org/proposals/327-pow-over-intro.html)、[prop 362](https://spec.torproject.org/proposals/362-update-pow-control-loop.html)） | 1.3.x 设计/铺地；1.4.6 换成 prop 362 控制环；1.5.0 实验支持（[!3106](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3106)）。稳定化仍开放：[arti#1751](https://gitlab.torproject.org/tpo/core/arti/-/issues/1751) | 有（0.4.8 `HiddenServicePoW*`，默认关） | **MISSING** | 无 | **P1** 客户端：目标服务开启 PoW 时才能连上；**P2** 托管：gotor 托管未上线前不要做。未 required |
| **Vanguards-lite** | **1.2.2 默认** lite（[#1272](https://gitlab.torproject.org/tpo/core/arti/-/issues/1272) 等）；1.2.3 修 TROVE-2024-003 / [arti#1409](https://gitlab.torproject.org/tpo/core/arti/-/issues/1409)（电路少一跳） | 有（默认 lite） | **MISSING** | 无（仅文档「考虑使用」） | **P1**（mainnet HS 默认防御，不是 proto required）。见上文清单第 10 项 |
| **RPC / 嵌入 API** | RPC **1.4.2 稳定**；2.1.0/2.2.0 非阻塞与 superuser；2.0.0 `inet-auto`。嵌入库自 1.0.0 起是 `arti-client`（2.0.0 起 `arti` crate API 标 experimental） | 无 RPC；用 control-spec | RPC **MISSING**；Go 库嵌入 **PARTIAL**（`pkg/client`）；控制口子集 **WORKING** | `pkg/client`、`pkg/control` | **P2**。保持 C Tor 控制口 + Go API；不要为追 Arti RPC 破坏现有控制器 |
| **arti-relay 中继工作** | 2.0.0 TLS 服务端 / `ChanMgr` / reactor；2.2.0 入向 TLS+认证；1.9.0 入向 DATA、初始化 guard/circ/dir；2.5.1 入向消息、BeginDir/Resolve、未完成 DirMirror、描述符上传（[#2549](https://gitlab.torproject.org/tpo/core/arti/-/issues/2549)）。**未宣布可跑生产中继** | 完整中继 | **PARTIAL**（实验，未进共识） | `pkg/relay/*` | **P1** 跟共识硬门槛（Running、DirCache/HS*/LinkAuth），不是复制 Arti 未完成内部件 |
| **目录 / consensus / protover** | 1.4.3 缺协议则退出（[!2929](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2929)）；`MicroDesc` 更名为 `Microdesc`。1.5.0 `tor-netdoc` API 大改。2.2.0 consdiff **生成**后端；2.5.0 编解码 router/microdesc/consensus；2.5.1 开始算共识 | 权威+缓存完整；客户端 consdiff=DirCache=2 | 客户端 **WORKING**；对外缓存 **MISSING** | `pkg/directory/` | 客户端 **P0 已跟**。新投票/共识格式：**P2**，等共识行要求。中继对外 DirCache：**P1**（required-relay） |
| **FlowCtrl=2 / 拥塞控制**（[prop 324](https://spec.torproject.org/proposals/324-rtt-congestion-control.html)） | 1.4.3 握手铺地；1.5.0 实验；1.4.6 XON/XOFF；**2.4.0 标 stable**（`flowctl-cc`）；**2.5.0 默认构建启用**。2.5.1 修 XON 把 Bps 当成 bps 的 8 倍限速 bug | 有（现网默认 Vegas） | 客户端 **WORKING** | `pkg/circuit/vegas.go`、`pkg/circuit/ccparams.go` | **P0**（recommended FlowCtrl=1-2）。HS 上协商仍是 Arti 实验 → **P2** |
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
