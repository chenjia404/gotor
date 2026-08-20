# 中继受理 ESTABLISH_INTRO / ESTABLISH_RENDEZVOUS

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；**未**宣告 `HSIntro=` / `HSRend=` / `HSDir=`）

对照：[rend-spec-v3](https://spec.torproject.org/rend-spec/introduction-handshake.html)（引言点 ESTABLISH_INTRO / INTRO_ESTABLISHED；会合点 ESTABLISH_RENDEZVOUS / RENDEZVOUS_ESTABLISHED）。

本切片只讲中继 **作为最后一跳** 受理建立单元格。客户端侧 ESTABLISH 构造仍见 `pkg/onion/establish_intro.go`。

## 本切片已做

| 单元格 | 行为 |
|--------|------|
| ESTABLISH_INTRO（RELAY 32，StreamID=0） | 用本跳 `rend_circ_nonce`（ntor 展开 92 字节的后 20，或 ntor-v3 KDF 末 20）校验 MAC/签名；通过则回 INTRO_ESTABLISHED（38） |
| ESTABLISH_RENDEZVOUS（RELAY 33，StreamID=0） | 接受 20 字节 cookie；回 RENDEZVOUS_ESTABLISHED（39） |
| CREATE2 ntor / ntor-v3 | 把 `circ_nonce` 存进 `ServerCircuit`，供引言点 MAC |

重复 ESTABLISH、StreamID≠0、MAC 失败：DESTROY（protocol）。

## 明确未做（因此禁止 HS* proto）

- HSDir 收/服务 v3 描述符
- INTRODUCE1 转发 / INTRODUCE2 投递给托管服务
- RENDEZVOUS1 / RENDEZVOUS2
- 引言点/会合点生命周期、限速、官方 intro/rend 统计
- 真网官方客户端把本中继选为 intro/rend/HSDir 的证据

## 禁止

- 在 `proto` 写 `HSDir=` / `HSIntro=` / `HSRend=`
- 用电路 ntor 冒充 hs-ntor
- 把本切片单测写成「已具备 HS 中继角色」
