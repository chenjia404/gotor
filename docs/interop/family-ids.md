# Family ID（Desc=4 / happy families）

**日期**：2026-08-19  
**状态**：WORKING（2026-08-19 真实验收）

对照：

- path-spec [path-selection-constraints](https://spec.torproject.org/path-spec/path-selection-constraints.html)（Determining family membership）
- dir-spec [computing-microdescriptors](https://spec.torproject.org/dir-spec/computing-microdescriptors.html) `family-ids`
- proposal [321-happy-families](https://spec.torproject.org/proposals/321-happy-families.html)

## 实现（100% 纯 Go）

| 路径 | 作用 |
|------|------|
| `pkg/directory/family.go` | `InSameFamily` / `InSameFamilyPolicy` |
| `pkg/directory/microdesc.go` | 解析 `family-ids` |
| `pkg/path` | Guard/Middle/Exit 与 Conflux 第二腿按 family 避让 |
| `pkg/client` | 拉完 microdesc 后按 family 再验；冲突则重选（与 p6 同一模式） |

只面向**现行** microdesc 客户端：family ID 由权威从 `family-cert` 导出后写进 `family-ids`。客户端比较 ID 字符串，不在本地重算证书。

## 规则

1. **family-ids**（`use-family-ids`，缺省 1）：任一 ID 相同即为同家族，**不要求**双向 `family` 列表。
2. **family 列表**（`use-family-lists`，缺省 1）：双方必须列出对方。条目支持 `$HEX`、`$HEX=name` / `$HEX~name`、nickname（大小写不敏感）。
3. 共识 params 可关掉其中一种；缺省与最新 Tor 一样两者都开。
4. `family-ids` 的未识别格式按不透明字符串接受（spec SHOULD）。
5. 选路时 microdesc 通常尚未拉取，`FamilyIDs` 为空。`FetchMicrodescriptorsFor` 之后必须再验三跳；同家族则丢弃并重选（最多 5 次）。Conflux 第二腿还要与第一腿的 Guard/Middle 交叉检查。

## 禁止

- 只认旧 nickname/`family` 而忽略 `family-ids`
- 把单向 `family` 列表当成同家族
- 为过测试放宽双向列表或伪造 ID
- C 库 / CGO

## 真实验收

`TOR_INTEGRATION_TEST=1 go test ./integration/ -tags=integration -run TestRealFamilyIds`

**结果（2026-08-19）**：PASS。抽样 128 Running 得 `with_family_ids=44`；共享 ID 对 `InSameFamily=true`；选路补齐 microdesc 后 `diverse_paths=8/8`。
