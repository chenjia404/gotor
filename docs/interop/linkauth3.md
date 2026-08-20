# 中继校验 AUTHENTICATE（LinkAuth=3）

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；描述符已宣告 `LinkAuth=3`）

对照：[negotiating-channels](https://spec.torproject.org/tor-spec/negotiating-channels.html) AuthType `[00 03]` Ed25519-SHA256-RFC5705。

## 本切片已做

- 应答方记录握手抄本：SLOG = 本端写出至 AUTH_CHALLENGE（含 VERSIONS/CERTS/AUTH_CHALLENGE）；CLOG = 对端写出至 AUTHENTICATE 之前（含 VERSIONS/CERTS/VPADDING）。
- 发起方若发送 AUTHENTICATE，必须先有 CERTS（type 2/4/6/7），且 AUTH0003 的 CID/SID/CID_ED/SID_ED/SLOG/CLOG/SCERT/TLSSECRETS/SIG 全部匹配。
- TLSSECRETS 用 `EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003`，context 为 CID（SHA-256(PKCS#1 DER(RSA))）。
- 普通客户端只发 NETINFO，不强制认证。
- 描述符 `proto` 含 `LinkAuth=3`。

## 明确未做

- AuthType 1（已过时）校验
- 把 TLS 客户端证书当成 LinkAuth
- 真网权威/中继作为发起方完成认证的观察证据

## 禁止

- 宣告 `LinkAuth=3` 却跳过 AUTHENTICATE
- 无 TLS exporter 时接受伪造 AUTHENTICATE
