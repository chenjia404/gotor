# gotor 与官方 Tor 的兼容差距

**日期**：2026-08-20  
**对照官方版本**：C Tor **0.4.9.11**、Arti **2.5.1**（2026-08）  
**说明**：C Tor **0.4.8 已 EOL**，不要再按 0.4.8 行为实现或宣称兼容。  
**代码依据**：[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) + 仓库代码 + 真网/权威观察。  
**不要盲信**：[`ROADMAP.md`](../ROADMAP.md) 里的「~98% 完成」「Onion/Bridge 已完成」。

状态用语（与 `IMPLEMENTATION_STATUS.md` 对齐）：

| 标记 | 含义 |
|------|------|
| 已对齐 | 符合现行 spec，且有真网或官方向量证据 |
| PARTIAL | 有代码，但缺关键步骤、接线、或真网证明 |
| 官方有我们没有 | 官方 C Tor / Arti 具备，gotor 无可用实现 |

禁止事项对**每一项后续实现**都适用：禁止全零 key fallback、禁止 mock/本地桩当完成、禁止为过测试放松协议校验、禁止 CGO、禁止把「ORPort 通了」写成「已进共识」。

---

## 声明

gotor **不是** Tor Project 官方实现，也未受其监督或背书。  
**不能当作人身安全级匿名工具。** 需要匿名时请用 [Tor Browser](https://www.torproject.org/download/) 或官方 [Arti](https://gitlab.torproject.org/tpo/core/arti) / [C Tor](https://gitlab.torproject.org/tpo/core/tor)。

---

## 一句话定位

**客户端接近官方推荐协议；中继实验性（描述符可被权威收下，但未进共识、不能当中间跳）；洋葱托管未上线。**

---

## 按角色对照

| 角色 | 已对齐（含真网证据） | PARTIAL | 官方有我们没有 |
|------|----------------------|---------|----------------|
| **客户端** | 共识 9/9 验签、`cached-certs` 重启 0 次 `/tor/keys/fp`、DirCache=2 consdiff、microdesc、Link TLS+CERTS type 7、默认 ntor-v3 CREATE2/EXTEND2、3-hop SOCKS5 `IsTor=true`、RESOLVE、FlowCtrl=2 Vegas soak、Relay=5/6 CGO、Conflux=1、EXTEND2 IPv6、`p`/`p6` 出口策略、Desc=4 family-ids、Padding=2 协商 ACK、v3 `.onion` 客户端 HTTP 200 | Guard 选路与官方指纹仍可能有差异；Fast/MiddleOnly/BadExit 已强制但未单独真网标 WORKING；circpad token-removal | Vanguards-lite；完整 PT/网桥客户端生产路径；与 Tor Browser 同级的隔离/反指纹 |
| **中继** | 描述符可 POST 到权威并获 HTTP 200；交叉证书（onion-key-crosscert / ntor-onion-key-crosscert）与 Ed25519 摘要签名按 dir-spec 生成 | ORPort 监听；CREATE2 经典 ntor / ntor-v3；EXTEND2→CREATE2→EXTENDED2 剥层转发（仅本地/单测）；出口策略解码与 EXIT 流（实验）；`DirCacheServer` 骨架（未接到 `Server.Start`） | **进共识 `Running`**；self-test / 可达性电路；真网当中间跳；对外 DirCache=2（含 consdiff、`/tor/keys`、BEGIN_DIR 完整）；HSDir=2 / HSIntro=4-5 / HSRend=2 中继角色；LinkAuth=3 服务端；relay 侧 CGO；官方级 DoS；完整 extra-info |
| **洋葱托管** | 无（未上线） | ESTABLISH_INTRO；ntor `rend_circ_nonce`；BEGIN_DIR 上传；type-8 致盲证书 + 双层加密密封；torrc `HiddenService*` | **真网发布后被客户端找到并完成 INTRODUCE2→RENDEZVOUS**；官方 intro/rend 生命周期与限速；vanguards |
| **网桥 / PT** | 无 | `pkg/pt` 子进程框架、obfs4 配置解析、本地 integration 桩 | 向 BridgeAuth 生产发布；客户端经官方 PT 进网；网桥描述符/统计与 C Tor 对齐 |
| **控制端口** | AUTHENTICATE；**AUTHCHALLENGE SAFECOOKIE**；COOKIE / HASHEDPASSWORD；GETINFO/GETCONF/SETCONF 子集；SETEVENTS（CIRC/STREAM/BW/NOTICE 等）；SIGNAL；MAPADDRESS | GETINFO 键远少于 control-spec；`version` 仍回 `go-tor 0.1.0`（CLI `--version` 已报 `0.4.9.11 (gotor)`） | ADD_ONION / DEL_ONION；EXTENDCIRCUIT / ATTACHSTREAM；HSFETCH / HSPOST；USEFEATURE；完整 `circuit-status` / `ns/id` / `desc/id` 等 |

近期：**G123**（TLS 会话恢复绕过证书校验）已用 `VerifyConnection` 修好，见 `pkg/connection/connection.go`（2026-08，`2612779`）。客户端 Link 身份校验仍以 CERTS 为准，不把 TLS 成功当成身份成功。

### de5 现状（2026-08-19）

公开中继 **de5**：描述符权威 **HTTP 200**，投票可见 **Valid / V2Dir**，**缺 Running**，**未进共识**。ORPort 通 ≠ 上线。

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

做完一项：改本文件状态 + `IMPLEMENTATION_STATUS.md`，写真网路径 / 权威投票 / 共识指纹。一个 PR 只做一项。

### 1. 中继进共识（Running / self-test）

- [ ] **状态**：PARTIAL（描述符可上传；de5 有 Valid/V2Dir、无 Running）
- **现有代码**：`pkg/relay/descriptor.go`、`pkg/relay/publisher.go`、`pkg/relay/server.go`（`startPublisher`）、`pkg/relay/descriptor_verify.go`
- **要做**：对照 C Tor `router.c` / `routerkeys.c` 的 reachability self-test（经电路连回自己的 ORPort）；修复 `proto` 只宣告已实现能力；确认权威投票出现 `Running` 且进入共识 `r` 行。
- **禁止**：把权威 200 或 Valid 写成「已进共识」；伪造 Running；全零 identity / ntor key。

### 2. 真网当中间跳

- [ ] **状态**：PARTIAL（转发代码在；无「官方客户端经 gotor middle 出网」证据）
- **现有代码**：`pkg/relay/circuit_handler.go`、`pkg/relay/extension.go`、`pkg/relay/forwarding.go`、`pkg/relay/forwarding_extend.go`、`pkg/relay/or_listener.go`
- **要做**：被真实 Guard/客户端 EXTEND2 选中；CREATED2 + 剥层转发 + 回程加密；官方 `tor` 建 3-hop 且 middle 为 gotor。
- **禁止**：只用 mocknet / 本地两进程互连宣称 WORKING；Ed25519 误当经典 ntor NODEID。

### 3. DirCache 对外服务

- [ ] **状态**：PARTIAL（客户端 **拉** consdiff 已对齐；中继 **提供** 目录缓存未上线）
- **现有代码**：客户端 `pkg/directory/consdiff.go`、`pkg/directory/directory.go`；中继骨架 `pkg/relay/dirport.go`（`DirCacheServer`）。配置有 `DirCache`/`DirPort`（`pkg/config/config.go`），**未**接到 `relay.Server.Start`。
- **要做**：BEGIN_DIR + 可选明文 DirPort；服务 `consensus-microdesc`、microdesc、**consdiff**、`/tor/keys/fp`；通过权威 V2Dir 且被其他客户端当缓存使用。`dirport.go` 的 `http.ReadRequest(nil)` 不能当完成。
- **禁止**：只开 DirPort 回 200 空体；宣告 `DirCache=2` 却不会 limited-ed diff；用明文 DirPort 拉 HS 描述符并宣称安全。

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

## 实现时怎么用这份文档

1. 先读本节对应项的「现有代码」和「禁止」，再改代码。
2. 协议细节以现行 [tor-spec](https://spec.torproject.org/) / C Tor 0.4.9.11 / Arti 2.5.1 为准，不以过期 ROADMAP、GAPS、AUDIT 自评为准。
3. 默认 `go test ./...` 不得访问公网。真实验收：`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration`。
4. 互操作字节级说明在 `docs/interop/`；本文件只跟踪**与官方的差距和优先级**。
5. 相关但不替代本文件：[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)（按模块状态）、[`RELAY.md`](RELAY.md)（中继操作）、[`TOR_DROPIN.md`](TOR_DROPIN.md)（CLI/torrc）、[`SECURITY_LIMITATIONS.md`](SECURITY_LIMITATIONS.md)（安全边界）。[`COMPATIBILITY_TESTING.md`](COMPATIBILITY_TESTING.md) 只讲如何跑对照测试，不是差距清单。
