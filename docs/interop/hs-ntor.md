# hs-ntor（rend-spec-v3 NTOR-WITH-EXTRA-DATA）

**日期**：2026-08-19  
**状态**：WORKING（官方向量 Appendix G.1 全绿；RENDEZVOUS1 已改用 hs-ntor）

对照：

- [rend-spec introduction / rendezvous](https://spec.torproject.org/rend-spec/)
- [Appendix G test vectors](https://spec.torproject.org/rend-spec/test-vectors.html)
- C Tor `src/core/crypto/hs_ntor.c`
- Arti `tor-hscrypto::ops::hs_mac` / `tor-proto::hs_ntor`

## 实现（100% 纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/crypto/hs_ntor.go` | HsMAC、IntroKeys、ServiceRend、ClientRend、ExpandCircuitKeys |
| `pkg/onion/rendezvous1.go` | RENDEZVOUS1 使用 `HsNtorServiceRend`（禁止电路 ntor） |

### 常量

- `PROTOID = tor-hs-ntor-curve25519-sha3-256-1`
- `MAC(k,m) = SHA3-256(htonll(len(k)) || k || m)`
- Intro KDF：`SHAKE256(intro_secret \| t_hsenc \| m_hsexpand \| subcred)`
- Rend：`NTOR_KEY_SEED = MAC(rend_secret, t_hsenc)`；`AUTH = MAC(auth_input, t_hsmac)`
- 电路密钥：`SHAKE256(NTOR_KEY_SEED \| m_hsexpand)` → Df\|Db\|Kf\|Kb（各 32）

### 与电路 ntor 的区别

| | 电路 ntor | hs-ntor |
|--|-----------|---------|
| ID | RSA fingerprint 20B | Ed25519 AUTH_KEY 32B |
| 哈希 | HMAC-SHA256 | SHA3-256 MAC + SHAKE256 |
| 密钥长度 | AES-128 / SHA1 digest | AES-256 / SHA3-256 digest |

## 官方向量

`go test ./pkg/crypto/ -run 'HsNtorOfficial|HsMACTor'` 对照 Appendix G.1：

- ENC_KEY / MAC_KEY / X
- AUTH_INPUT_MAC / NTOR_KEY_SEED / Y

## 禁止

- 用电路 `NtorServerHandshake` 冒充 HS rendezvous
- 全零 key fallback
- CGO
