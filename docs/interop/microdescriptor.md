# Microdescriptor 互操作记录

## Tor Spec（dir-spec）

- `ntor-onion-key` 与 `id ed25519` 均在**同一行**
- microdescriptor digest = SHA256(完整文档)，再 **base64 且去掉 padding**
- 共识 `m` 行使用该 digest
- 共识 `r` 行 identity = RSA fingerprint 的 **无 padding base64**（20 字节）

## C Tor

- `routerparse.c` / `microdesc.c`：按完整文档字节哈希
- 拉取：`GET /tor/micro/d/digest1-digest2-...`

## Arti

- `tor-dirmgr` / `tor-netdoc`：同样按文档 SHA256 + raw base64

## gotor 原行为（错误）

- 把 `id ed25519` 的密钥读成**下一行**
- digest 用 `Join(lines,"\n")` + **带 padding** 的 StdEncoding
- 批量串行 + 10s timeout，失败只 warn
- 缺少密钥时 CREATE2 使用 `make([]byte,32)` 全零 fallback

## 最终选择

- 按文档切分并哈希，digest 无 padding
- 同行解析 `id ed25519`
- 并行拉取；路径上的 3 个 relay 必须定向拉齐密钥
- 缺少密钥返回明确 error，禁止 zero-key fallback
