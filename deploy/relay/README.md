# 公网中继测试部署（de5-ssd）

## 要点

- 镜像：`chenjia404/gotor:latest`（Docker Hub；本机构建推送，服务器只 pull）
- 数据：`./data` 挂载，属主需为 `65532:65532`
- 公网只映射 **9001**（ORPort）
- SOCKS / metrics 绑在 compose 网络（`gotor:9050` / `gotor:9052`），不映射宿主机。loadgen 不再共享中继网络命名空间，中继重启后探测不会一直假失败
- `ConnLimit 10000`、`mem_limit 4g`、`GOMEMLIMIT=3GiB`：避免默认 1000 连接和 2g 上限把 middle 打满
- 控制口仍只听 `127.0.0.1:9051`

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

`check.sh` 只看容器状态和最近探测，不再按网络命名空间重建 loadgen。
