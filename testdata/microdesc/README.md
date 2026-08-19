# Microdescriptor 长期 fixture

`sample_v3.txt`：确定性 microdescriptor 文档（不含 `@type` 头）。
`sample_v3.digest`：`base64.RawStdEncoding(SHA256(doc))`，与共识 `m` 行一致。

用于离线回归：解析 ntor / ed25519 / family / p / p6 / a，且 digest 匹配。
