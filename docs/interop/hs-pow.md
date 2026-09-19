# 洋葱服务客户端 PoW（hspow-spec v1）

**日期**：2026-09-19  
**状态**：PARTIAL（客户端解析 + Equi-X 求解 + INTRODUCE1 内层扩展；**无**真网 PoW 服务验收；**无**托管侧验证/控制环）

对照：

- [hspow-spec v1 Equi-X + Blake2b](https://spec.torproject.org/hspow-spec/v1-equix.html)
- [rend-spec INTRODUCE PROOF_OF_WORK](https://spec.torproject.org/rend-spec/introduction-protocol.html)
- C Tor `test_crypto_equix` / Arti `hashx`·`equix` 公开向量

## 实现（纯 Go，无 CGO）

| 路径 | 作用 |
|------|------|
| `pkg/crypto/hashx` | HashX 程序生成 + 解释器（Blake2b 盐 `HashX v1`） |
| `pkg/crypto/equix` | Equihash(60,3) 求解/验证 |
| `pkg/onion/pow.go` | `pow-params v1`、挑战串、Blake2b-32 工作量、INTRODUCE1 EXT 0x02 |

未链接 LGPL 的 C Equi-X；不宣告任何 HS* proto。托管侧 PoW 验证与 prop 362 控制环不在本切片。

## 协议要点

- 描述符第二层：`pow-params v1 <seed-b64> <suggested-effort> <YYYY-MM-DDTHH:MM:SS>`
- `suggested-effort=0`：服务接受 PoW 但首次连接可不解
- 挑战：`P || ID || C || N || htonl(E)`，`P="Tor hs intro v1\0"`，`ID=KP_hs_blind_id`
- 工作量：`R = ntohl(blake2b_32(challenge || S))`，`R * E` 不得溢出 uint32
- INTRODUCE1 **加密段**扩展：TYPE=0x02，LEN=41（scheme/nonce/effort/seed-head/solution）

## 命令

```bash
go test ./pkg/crypto/hashx ./pkg/crypto/equix ./pkg/onion -count=1 -timeout 120s -run 'HashX|Equix|PoW|OnionPoW'
```

## 成功条件

- HashX / Equi-X 官方向量通过
- 描述符含 `pow-params v1` 且 effort>0 时，INTRODUCE1 内层带 EXT 0x02
- **不要**把无 PoW 的 `.onion` HTTP 200 写成「PoW WORKING」
