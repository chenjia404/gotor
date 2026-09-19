# extra-info 与 extra-info-digest

**日期**：2026-08-20  
**状态**：PARTIAL（离线单测；权威曾对无 digest 的单独 extra-info 回 400；出站中间跳 OR 已计入）

对照：[dir-spec extra-info](https://spec.torproject.org/dir-spec/extra-info-document-format.html)、[server descriptor extra-info-digest](https://spec.torproject.org/dir-spec/server-descriptor-format.html)、C Tor `router.c` / `rephist.c`。

## 本切片已做

- 先签 extra-info，再在 server descriptor `bandwidth` 与 `onion-key` 之间写 `extra-info-digest SHA1 SHA256`。
- SHA-1：大写 hex，覆盖到 `router-signature\n`（不含 PEM）。
- SHA-256：无填充 base64（43 字符），覆盖**整份含签名**（dir-spec 记载的 C Tor 实现差）。
- `published` 两边同一时刻；`extra-info Nickname Fingerprint` 指纹 40 位大写 hex、无空格。
- Ed25519 + RSA 双签名；发布前自检。
- 与 C Tor 一样把 router + extra-info **拼成一次 POST**（不再先发无 digest 的描述符再单独 POST extra-info）。
- 带宽历史只写**已完成**的 900s 观测格；停机空档不补零。无观测则不写 `write-history` / `read-history`。
- `ipv6-write-history` / `ipv6-read-history`：同一时间轴上仅 IPv6 OR（不含 IPv4-mapped）；总量仍含 IPv6。已完成格里无 IPv6 字节则不写这两行。IPv4 格对应位置写 0，不另造格。
- 观测来自 **入站 OR TCP** 与 **出站中间跳 OR TCP**（TLS 之下的套接字）；可读写 C Tor `DataDirectory/state` 的 `BWHistoryReadValues` / `BWHistoryWriteValues` / `BWHistoryIPv6*` / `*Ends`。**最后一值是未完成桶**，`*Ends` 是该桶结束时刻；未到点不写入 extra-info。`AvoidDiskWrites` 时不落盘。出口流 TCP 不计入本项。
- 描述符 `bandwidth` 第三个数（observed）：已完成 900s 格 `min(max(read/s), max(write/s))`，≤ burst；无观测写 0，不用配置平均冒充。
- `conn-bi-direct`：按 C Tor `connstats.c` 每 10s 把每条 OR 连接分成 below（读写合计 <20480）/ read（读≥10×写）/ write / both；**满 24h 且该窗内至少有一次分类才写**。未完成窗不写。
- `ipv6-conn-bi-direct`：同一窗内仅 IPv6 OR（不含 IPv4-mapped）；无 IPv6 分类不写。
- `dirreq-stats-end` / `dirreq-v3-resp`：v3 网络状态（ns/microdesc/diff）HTTP 应答；满 24h 且有计数才写；计数向上取 4。
- `dirreq-v3-ips` / `dirreq-v3-reqs`：无 geoip，一律 `??=N`（规范允许无法映射时用 `??`）；ips 为 24h 窗内 unique IP（DirPort 对端或 BEGIN_DIR 相邻 OR），reqs 为请求次数；向上取 8。不写国家码。空地址不计入 ips。
- `dirreq-v3-direct-dl` / `dirreq-v3-tunneled-dl`：DirPort HTTP 为 direct，BEGIN_DIR 为 tunneled；HTTP 200 且未满 10 分钟记 `complete`；开始发送后 10 分钟未完成记 `timeout`；测量期末仍在传且未满 10 分钟记 `running`。满 24h 且该通道有上述计数才写。无字节速率观测，不写 min/d1/…/max。
- `exit-stats-end` / `exit-kibibytes-written` / `exit-kibibytes-read` / `exit-streams-opened`：仅 RELAY_BEGIN 成功出口 TCP；BEGIN_DIR / RESOLVE 不计。C Tor interesting ports 分列，其余 `other`。KiB 向上取整，流数向上取 4。满 24h 且有观测、且策略允许退出才写。

## 明确未做

- `dirreq-v3-ips` / `dirreq-v3-reqs` 的真实国家码（无 GeoIP 库）
- `hidserv-*` / `padding-counts`（无 24h 观测不写）
- `dirreq-v3-*-dl` 的 B/s 分位数（无下载速率观测不写）
- 进程空闲但在跑时的全零格（无心跳；有流量的格才入列）
- 真网权威归档 extra-info 的观察证据

## 禁止

- 把配置里的 `RelayBandwidthRate` / Burst 写成 history 或 `bandwidth` observed
- 无观测却写假 `write-history` / `read-history` / `ipv6-*-history`
- 无观测却把 average 写成 `bandwidth` 第三个数
- 空 extra-info 当「已实现完整」
- 公开材料写主机、IP、指纹
