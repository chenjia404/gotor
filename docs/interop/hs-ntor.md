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
| `pkg/onion/rendezvous1.go` | RENDEZVOUS1 使用 `HsNtorServiceRend` |
| `pkg/onion/introduce2.go` | INTRODUCE2：`X\|\|C\|\|M` + HsMAC + AES-256-CTR |
| `pkg/onion/subcred.go` | `N_hs_cred` / `N_hs_subcred` |

### 常量

- `PROTOID = tor-hs-ntor-curve25519-sha3-256-1`
- `MAC(k,m) = SHA3-256(htonll(len(k)) || k || m)`
- Intro KDF：`SHAKE256(intro_secret \| t_hsenc \| m_hsexpand \| subcred)`
- Rend：`NTOR_KEY_SEED = MAC(rend_secret, t_hsenc)`；`AUTH = MAC(auth_input, t_hsmac)`
- 电路密钥：`SHAKE256(NTOR_KEY_SEED \| m_hsexpand)` → Df\|Db\|Kf\|Kb（各 32）

### INTRODUCE1/2

- Header `H` = LEGACY_KEY_ID(20 零) + AUTH_KEY… + EXTENSIONS
- `ENCRYPTED = X \| C \| M`，`M = MAC(MAC_KEY, H\|X\|C)`
- 服务端：`HsNtorServiceIntroKeys(b, X, AUTH_KEY, subcred)` 解密
- 客户端：`BuildIntroduce1Encrypted` / `HsNtorClientIntroKeys`

## 官方向量

`go test ./pkg/crypto/ -run 'HsNtorOfficial|HsMACTor'`
`go test ./pkg/onion/ -run 'ParseIntroduce2Official'`

对照 Appendix G.1：ENC/MAC/AUTH/SEED 与整包 INTRODUCE 解密。

## 禁止

- 用电路 `NtorServerHandshake` 冒充 HS rendezvous
- INTRODUCE 仍用 HKDF-SHA256 / HMAC-SHA256
- 全零 key fallback
- CGO
