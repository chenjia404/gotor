# 公网中继测试部署（de5-ssd）

## 要点

- 镜像：`chenjia404/gotor:latest`（Docker Hub；本机构建推送，服务器只 pull）
- 数据：`./data` 挂载，属主需为 `65532:65532`
- 公网只映射 **9001**（ORPort）
- `ConnLimit 10000`、`mem_limit 2g`：避免默认 1000/512m 把 middle 打满拒连
- `loadgen` 使用 `network_mode: service:gotor`；**gotor 单独重启后必须 recreate loadgen**，否则 SOCKS/metrics 探针全失败

## 部署

```bash
# 本机
docker build -t chenjia404/gotor:latest .
docker push chenjia404/gotor:latest

# 服务器 /home/gotor（或本目录）
cp torrc.example torrc   # 按需改 Nickname/Address/ContactInfo
mkdir -p data logs
chown -R 65532:65532 data
docker compose pull gotor
docker compose up -d --force-recreate --build
sh ./check.sh
```

## 巡检

`check.sh` 会检测 loadgen/gotor 网络命名空间是否一致，不一致时自动 `force-recreate loadgen`。
