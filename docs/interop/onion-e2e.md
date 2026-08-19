# .onion 客户端 e2e（真实验收）

## 已验证路径

1. KEYBLIND + HSDir 哈希环 + 匿名 3-hop BEGIN_DIR 拉描述符
2. ESTABLISH_RENDEZVOUS（Fast 会合点）
3. 引言点 3-hop + INTRODUCE1（含 RP ntor 密钥与 link-specifiers）
4. RENDEZVOUS2 + hs-ntor AUTH 校验 + 电路密钥展开

## 命令

```bash
TOR_INTEGRATION_TEST=1 go test -tags=integration -run TestRealOnionConnect -v
```

## 结果示例

Tor Project onion：`onion connect OK rendezvous_circuit=…`，`hs-ntor rendezvous verified`。

## 剩余

- 在会合电路上发送 RELAY_BEGIN 并转发应用数据（SOCKS 数据面）
- INTRODUCE_ACK 显式等待

## 进度（续）

- `AddHSHop`：OPEN 电路可追加 hs-ntor 末跳（SHA3-256 + AES-256-CTR）
- SOCKS：`relayOnionServiceData` 先 `OpenStream`（RELAY_BEGIN）再转发
- 真实验收：Connect PASS；RELAY_BEGIN 等待 CONNECTED 仍超时（待查摘要/填充）
