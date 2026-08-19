# BEGIN_DIR（经 ORPort 的目录隧道）

**日期**：2026-08-19  
**状态**：WORKING（传输层已真实验收：BEGIN_DIR + GET consensus）；HS 描述符 URL 已改为 blinded key，完整 KEYBLIND 选钥仍可能影响描述符命中

对照：tor-spec [opening-streams](https://spec.torproject.org/tor-spec/opening-streams.html)；rend-spec 2.2.6 URL。

## 实现

| 路径 | 作用 |
|------|------|
| `pkg/circuit/begindir.go` | `OpenDirStream` / `FetchHTTPViaBeginDir` |
| `pkg/onion/begindir.go` | `BegindirFetcher`：1-hop + BEGIN_DIR GET |
| `pkg/onion` HSDir | 优先 BEGIN_DIR，回退 HTTP DirPort |
| URL | `/tor/hs/3/<base64.RawStd(blinded-pubkey)>`（不是 H(blinded)） |

## 真实验收

`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration -run TestRealHSDirFetch`

- BEGIN_DIR 拉 `/tor/status-vote/current/consensus-microdesc` → 200 + body
- 描述符拉取若 503：多为 KEYBLIND 未完整实现导致索引错误

## 禁止

- 用 DirPort HTTP 宣称现代 HSDir WORKING
- CGO
