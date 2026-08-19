# gotor 中继与出口

## 非出口

```bash
gotor ORPort 9001 Nickname gotorMiddle ExitRelay 0
```

## 出口

```bash
gotor -f examples/torrc.exit.sample
# 或
gotor ORPort 9001 ExitRelay 1 ReduceExitPolicy 1 \
  ExitPolicy 'accept *:80' ExitPolicy 'accept *:443' ExitPolicy 'reject *:*'
```

### 出口 torrc 键

- `ExitRelay`、`ExitPolicy`、`ExitPolicyRejectPrivate`、`ReduceExitPolicy`、`IPv6Exit`

### 行为

- 电路末端解密 RELAY（Tor1 AES-CTR + digest）
- `RELAY_BEGIN` → 策略检查 → TCP 拨号 → `RELAY_CONNECTED` → 双向 `DATA` / `END`
- 默认未配置 `ExitPolicy` 且 `ExitRelay 1` 时使用精简端口集（类 ReduceExitPolicy）

## 未完成

向权威发布描述符、多跳 EXTEND 完整转发真网验收、DirPort。
