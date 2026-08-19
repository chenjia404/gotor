# KEYBLIND + HSDir 选路 / 描述符拉取

## KEYBLIND（rend-spec Appendix A）

- `h = SHA3_256("Derive temporary signing key\0" | A | basepoint_str | N)`
- `N = "key-blind" | INT_8(period) | INT_8(1440)`
- `A' = clamp(h) · A`（`filippo.io/edwards25519`）
- 时间周期：`(unix/60 - 720) / 1440`（对齐 C Tor）

## HSDir 哈希环

- `hs_index = SHA3_256("store-at-idx" | blinded | replica | period_len | period)`（replica 从 1 起）
- `hsdir_index = SHA3_256("node-idx" | ed25519_id | SRV | period | period_len)`
- 拉取用 current/previous SRV 合并负责节点；spread_fetch=3

## 匿名 BEGIN_DIR

HSDir 拒绝单跳：`BegindirFetcher` 建 Guard→Middle→HSDir 三跳后 `RELAY_BEGIN_DIR`。

## 描述符

- 签名前缀：`Tor onion service descriptor sig v3`
- 证书类型 8，由致盲公钥验签
- 双层解密：SHAKE256 + AES-256-CTR + SHA3 MAC

## 真实验收

`TOR_INTEGRATION_TEST=1 go test -tags=integration -run TestRealHSDirFetch`

结果示例：Tor Project onion，`intro_points=8`，`auth=32 enc=32 links≥3`。
