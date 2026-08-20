# extra-info 与 extra-info-digest

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；权威曾对无 digest 的单独 extra-info 回 400）

对照：[dir-spec extra-info](https://spec.torproject.org/dir-spec/extra-info-document-format.html)、[server descriptor extra-info-digest](https://spec.torproject.org/dir-spec/server-descriptor-format.html)、C Tor `router.c` / `rephist.c`。

## 本切片已做

- 先签 extra-info，再在 server descriptor `bandwidth` 与 `onion-key` 之间写 `extra-info-digest SHA1 SHA256`。
- SHA-1：大写 hex，覆盖到 `router-signature\n`（不含 PEM）。
- SHA-256：无填充 base64（43 字符），覆盖**整份含签名**（dir-spec 记载的 C Tor 实现差）。
- `published` 两边同一时刻；`extra-info Nickname Fingerprint` 指纹 40 位大写 hex、无空格。
- Ed25519 + RSA 双签名；发布前自检。
- 与 C Tor 一样把 router + extra-info **拼成一次 POST**（不再先发无 digest 的描述符再单独 POST extra-info）。
- 带宽历史只写**已完成**的 900s 观测格；停机空档不补零。无观测则不写 `write-history` / `read-history`。
- 观测来自 OR 入站 TCP 套接字读写；可读写 C Tor `DataDirectory/state` 的 `BWHistoryReadValues` / `BWHistoryWriteValues` / `*Ends`（不改官方键语义）。`AvoidDiskWrites` 时不落盘。

## 明确未做

- 出站中间跳 OR 连接字节（尚未计入）
- `conn-bi-direct` / `dirreq-*` / `exit-*` / `hidserv-*` / `padding-counts`（无 24h 观测不写）
- 进程空闲但在跑时的全零格（无心跳；有流量的格才入列）
- 真网权威归档 extra-info 的观察证据
- 描述符 `bandwidth` 第三个数仍可来自配置默认，不是本切片的观测值

## 禁止

- 把配置里的 `RelayBandwidthRate` / Burst 写成 history
- 无观测却写假 `write-history` / `read-history`
- 空 extra-info 当「已实现完整」
- 公开材料写主机、IP、指纹
