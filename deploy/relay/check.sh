#!/bin/sh
# 中继稳定性快照
set -eu
cd "$(dirname "$0")"

echo "===== compose ps ====="
docker compose ps -a
echo "===== restart / oom ====="
docker inspect gotor-relay gotor-loadgen --format '{{.Name}} restart={{.RestartCount}} oom={{.State.OOMKilled}} status={{.State.Status}} started={{.State.StartedAt}}' 2>/dev/null || true
echo "===== stats ====="
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' gotor-relay gotor-loadgen 2>/dev/null || true
echo "===== loadgen last 20 ====="
tail -n 20 ./logs/loadgen.jsonl 2>/dev/null || echo '(no loadgen log yet)'
echo "===== loadgen success rate (last 200 lines) ====="
if [ -f ./logs/loadgen.jsonl ]; then
  tail -n 200 ./logs/loadgen.jsonl | awk '
    /"ok":true/ {ok++}
    /"ok":false/ {bad++}
    END {total=ok+bad; if(total==0) print "no samples"; else printf "ok=%d fail=%d rate=%.1f%%\n", ok, bad, (ok*100/total)}
  '
fi
echo "===== gotor logs (last 40) ====="
docker logs --tail 40 gotor-relay 2>&1 || true
