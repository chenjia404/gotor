# 中继受理 ESTABLISH / INTRODUCE1 / RENDEZVOUS1 与 HSDir 收/服

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；**未**宣告 `HSIntro=` / `HSRend=` / `HSDir=`）

对照：

- [rend-spec-v3 introduction](https://spec.torproject.org/rend-spec/introduction-protocol.html)
- [rend-spec-v3 rendezvous](https://spec.torproject.org/rend-spec/rendezvous-protocol.html)
- [rend-spec-v3 HSDir](https://spec.torproject.org/rend-spec/hsdesc-encrypt.html)

本文件只讲中继 **作为最后一跳 / 目录缓存** 的行为。客户端构造仍见 `pkg/onion/`。

## 本切片已做

| 单元格 / 路径 | 行为 |
|----------------|------|
| ESTABLISH_INTRO（32） | 用 `rend_circ_nonce` 校验；按 AUTH_KEY 登记；回 INTRO_ESTABLISHED（38） |
| INTRODUCE1（34） | 解析 v3 AUTH_KEY；命中则原样转发 INTRODUCE2（35）给服务电路，并向客户端回 INTRODUCE_ACK（40）。未知=NOT_RECOGNIZED，坏格式=BAD_MESSAGE_FORMAT |
| ESTABLISH_RENDEZVOUS（33） | 接受 20 字节 cookie 并登记；回 RENDEZVOUS_ESTABLISHED（39） |
| RENDEZVOUS1（36） | cookie **一次性取出**；命中则向客户端电路发 RENDEZVOUS2（handshake，无 cookie），并把两条电路拼起来转发后续 RELAY |
| `POST /tor/hs/3/publish` | 验 type-8 / 正文签名；revision 只取自签名覆盖范围；按盲化公钥覆盖更高修订（≤100KiB，最多 64 份，3h TTL） |
| `GET /tor/hs/3/<base64>` | 按盲化公钥回已验签的 canonical 外层 |
| CREATE2 ntor / ntor-v3 | 保存 `circ_nonce` |

AUTH_KEY / cookie 冲突、电路已是另一角色、StreamID≠0、坏 MAC：DESTROY（protocol）。

## 明确未做（因此禁止 HS* proto）

- 引言点 DoS 扩展 / INTRODUCE2 令牌桶
- 会合点完整生命周期与官方统计
- HSDir 哈希环责任、副本、真网被选为 HSDir
- 真网官方客户端把本中继选为 intro/rend/HSDir 的证据

## 禁止

- 在 `proto` 写 `HSDir=` / `HSIntro=` / `HSRend=`
- 用电路 ntor 冒充 hs-ntor
- 把本切片单测写成「已具备完整 HS 中继角色」
