# Link VERSIONS CircID 宽度

## Tor Spec

- https://spec.torproject.org/tor-spec/cell-packet-format.html
- https://spec.torproject.org/tor-spec/preliminaries.html

`CIRCID_LEN(v) = 2` 当 `v < 4`；`= 4` 当 `v ≥ 4`。

VERSIONS 在版本协商之前发送，**始终按 `v = 0`**，因此 CircID 为 **2 字节**。

## C Tor / Arti

握手开始用 2 字节 CircID 收发 VERSIONS；协商到 v4/v5 后切换为 4 字节。

## gotor 原行为（错误）

所有 cell（含 VERSIONS）按 4 字节 CircID 编码。

线上字节：`00 00 00 00 07 ...`

对端按 2 字节解析：CircID=0，Command=0（PADDING），不会回 VERSIONS。表现为 TLS 成功后 `timeout waiting for VERSIONS`。

## 入站（中继 ORPort）

权威探测发 `00 00 | 07 | 00 06 | …`。协商前若按 4 字节 CircID 解析，第 5 字节 `0x06` 会被读成 CREATED_FAST，握手失败，权威无法投 Running。

入站路径：`pkg/relay/or_handler.go` 协商前 `circIDLen=2`，协商到 v≥4 后再切 4。CERTS / AUTH_CHALLENGE / NETINFO 用协商后的宽度。与出站 `SetCircIDLen` 对称。

## 最终选择

连接默认 `circIDLen=2`；VERSIONS 之后按协商版本调用 `SetCircIDLen(4)`（出站）或 handler `setCircIDLen`（入站）。
