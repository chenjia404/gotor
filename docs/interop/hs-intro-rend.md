# 中继受理 ESTABLISH / INTRODUCE1 / RENDEZVOUS1 与 HSDir 收/服

**日期**：2026-09-20  
**状态**：PARTIAL（离线单测；**未**宣告 `HSIntro=` / `HSRend=` / `HSDir=`）

对照：

- [rend-spec-v3 introduction](https://spec.torproject.org/rend-spec/introduction-protocol.html)
- [rend-spec-v3 rendezvous](https://spec.torproject.org/rend-spec/rendezvous-protocol.html)
- [rend-spec-v3 HSDir](https://spec.torproject.org/rend-spec/hsdesc-encrypt.html)

本文件只讲中继 **作为最后一跳 / 目录缓存** 的行为。客户端构造仍见 `pkg/onion/`。

## 本切片已做

| 单元格 / 路径 | 行为 |
|----------------|------|
| ESTABLISH_INTRO（32） | 用 `rend_circ_nonce` 校验；按 AUTH_KEY 登记；解析 `DOS_PARAMS`（type 0x01）覆盖共识限速；回 INTRO_ESTABLISHED（38） |
| INTRODUCE1（34） | 解析 v3 AUTH_KEY；命中则原样转发 INTRODUCE2（35）给服务电路，并向客户端回 INTRODUCE_ACK（40）。未知=NOT_RECOGNIZED，坏格式=BAD_MESSAGE_FORMAT。**令牌桶空：ACK NOT_RECOGNIZED（C Tor UNKNOWN_ID），不转发** |
| ESTABLISH_RENDEZVOUS（33） | 仅末端跳（未 EXTEND2）；接受 20 字节 cookie；未会合 cookie **10 分钟 TTL**、最多 128 个等待；回 RENDEZVOUS_ESTABLISHED（39） |
| RENDEZVOUS1（36） | 仅末端跳；cookie **一次性取出**；过期则 TIMEOUT 拆等待电路；命中则发 RENDEZVOUS2 并拼接 |
| CREATE2 ntor / ntor-v3 | 保存 `circ_nonce` |
| `POST /tor/hs/3/publish` | 验 type-8 / 正文签名；revision 只取自签名覆盖范围；按盲化公钥覆盖更高修订（≤100KiB，最多 64 份，3h TTL）；**环就绪后只接受本节点 spread_store 负责的盲化公钥（否则 404）**；接受后计入 extra-info `hidserv-dir-v3-onions-seen`（24h unique） |
| `GET /tor/hs/3/<base64>` | 按盲化公钥回已验签的 canonical 外层 |
| extra-info hidserv-v3-* | 满 24h 且有会合转发或 HSDir 接受才写；Laplace 混淆；无 v2 行 |

AUTH_KEY / cookie 冲突、电路已是另一角色、StreamID≠0、坏 MAC：DESTROY（protocol）。会合点拼接后每转发一格 RELAY 计入 `hidserv-rend-v3-relayed-cells`。

## 明确未做（因此禁止 HS* proto）

- 真网官方客户端把本中继选为 intro/rend/HSDir 的证据
- v2 `hidserv-rend-relayed-cells` / `hidserv-dir-onions-seen`（无 v2 洋葱）

## 禁止

- 在 `proto` 写 `HSDir=` / `HSIntro=` / `HSRend=`
- 用电路 ntor 冒充 hs-ntor
- 把本切片单测写成「已具备完整 HS 中继角色」
