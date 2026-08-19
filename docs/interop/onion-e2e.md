# .onion 客户端 e2e（真实验收）

## 已验证路径

1. KEYBLIND + HSDir 哈希环 + 匿名 3-hop BEGIN_DIR 拉描述符
2. ESTABLISH_RENDEZVOUS（Fast 会合点）
3. 引言点 3-hop + INTRODUCE1（RP ntor + link-specifiers）
4. RENDEZVOUS2 + hs-ntor AUTH + 电路密钥展开
5. HS 末跳（SHA3-256 + AES-256-CTR）安装
6. RELAY_BEGIN → RELAY_CONNECTED（虚拟端口 80）

## 关键修复

- `CloneHash` 支持 SHA3-256（否则 CONNECTED 被丢弃）
- `AddHSHop` 允许 OPEN 电路追加末跳
- INTRODUCE1 明文含会合点 link-specifiers

## 命令

```bash
TOR_INTEGRATION_TEST=1 go test -tags=integration -run TestRealOnionConnect -v
```

## 结果

`RELAY_BEGIN CONNECTED on rendezvous stream=1` — PASS。
