#!/bin/sh
# 中继稳定性快照；若 loadgen 与 gotor netns 脱节则自动 recreate loadgen
set -eu
cd "$(dirname "$0")"

ensure_loadgen_netns() {
  rpid=$(docker inspect -f '{{.State.Pid}}' gotor-relay 2>/dev/null || true)
  lpid=$(docker inspect -f '{{.State.Pid}}' gotor-loadgen 2>/dev/null || true)
  if [ -z "$rpid" ] || [ -z "$lpid" ] || [ "$rpid" = "0" ] || [ "$lpid" = "0" ]; then
    echo "===== loadgen netns: missing pid, recreate loadgen ====="
    docker compose up -d --force-recreate --no-deps loadgen
    return
  fi
  rns=$(readlink "/proc/$rpid/ns/net" 2>/dev/null || true)
  lns=$(readlink "/proc/$lpid/ns/net" 2>/dev/null || true)
  if [ -z "$rns" ] || [ -z "$lns" ] || [ "$rns" != "$lns" ]; then
    echo "===== loadgen netns mismatch (relay=$rns loadgen=$lns), recreating loadgen ====="
    docker compose up -d --force-recreate --no-deps loadgen
    sleep 2
  else
    echo "===== loadgen netns OK ($rns) ====="
  fi
}

echo "===== compose ps ====="
docker compose ps -a
ensure_loadgen_netns
echo "===== restart / oom ====="
docker inspect gotor-relay gotor-loadgen --format '{{.Name}} restart={{.RestartCount}} oom={{.State.OOMKilled}} status={{.State.Status}} started={{.State.StartedAt}}' 2>/dev/null || true
echo "===== stats ====="
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' gotor-relay gotor-loadgen 2>/dev/null || true
echo "===== loadgen last 20 ====="
tail -n 20 ./logs/loadgen.jsonl 2>/dev/null || echo '(no loadgen log yet)'
echo "===== loadgen success rate (last 500 lines) ====="
if [ -f ./logs/loadgen.jsonl ]; then
  tail -n 500 ./logs/loadgen.jsonl | awk '
    /"ok":true/ {ok++}
    /"ok":false/ {bad++}
    END {total=ok+bad; if(total==0) print "no samples"; else printf "ok=%d fail=%d rate=%.1f%%\n", ok, bad, (ok*100/total)}
  '
fi
echo "===== gotor logs (last 40) ====="
docker logs --tail 40 gotor-relay 2>&1 || true
