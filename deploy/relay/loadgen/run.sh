#!/bin/sh
# 通过本地 SOCKS 走清网/洋葱，并探测 OR/metrics，产生可观测负载
set -eu

LOG=${LOG:-/logs/loadgen.jsonl}
INTERVAL=${INTERVAL:-45}
SOCKS=${SOCKS:-127.0.0.1:9050}
METRICS=${METRICS:-127.0.0.1:9052}
ORPORT=${ORPORT:-127.0.0.1:9001}

mkdir -p "$(dirname "$LOG")"

log_json() {
  printf '%s\n' "$1" >> "$LOG"
}

now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

wait_socks() {
  i=0
  while [ "$i" -lt 120 ]; do
    if curl -sS --max-time 5 --connect-timeout 3 --socks5-hostname "$SOCKS" \
      -o /dev/null -w '' https://example.com >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  return 1
}

probe() {
  name=$1
  shift
  start=$(date +%s)
  body=$(mktemp)
  code=0
  if "$@" >"$body" 2>/tmp/probe.err; then
    code=0
  else
    code=$?
  fi
  elapsed=$(( $(date +%s) - start ))
  snippet=$(tr '\n' ' ' <"$body" | cut -c1-180 | sed 's/"/\\"/g')
  err=$(tr '\n' ' ' </tmp/probe.err 2>/dev/null | cut -c1-120 | sed 's/"/\\"/g')
  rm -f "$body"
  if [ "$code" -eq 0 ]; then
    log_json "{\"ts\":\"$(now)\",\"probe\":\"$name\",\"ok\":true,\"sec\":$elapsed,\"detail\":\"$snippet\"}"
    echo "$(now) OK  $name ${elapsed}s"
  else
    log_json "{\"ts\":\"$(now)\",\"probe\":\"$name\",\"ok\":false,\"sec\":$elapsed,\"err\":\"$err\"}"
    echo "$(now) ERR $name exit=$code ${elapsed}s $err"
  fi
}

echo "$(now) loadgen start, wait socks $SOCKS"
if ! wait_socks; then
  log_json "{\"ts\":\"$(now)\",\"probe\":\"bootstrap\",\"ok\":false,\"err\":\"socks not ready\"}"
  echo "$(now) socks not ready after 240s, keep retrying"
fi

while true; do
  probe health curl -sS --max-time 5 "http://$METRICS/health"
  probe metrics curl -sS --max-time 5 "http://$METRICS/metrics/json"
  # OR 监听：TLS 握手失败也算端口可达（curl 35=SSL，7=连不上）
  start=$(date +%s)
  curl -sS --max-time 4 -o /dev/null "https://$ORPORT" >/tmp/or.err 2>&1 || true
  orc=$?
  elapsed=$(( $(date +%s) - start ))
  if [ "$orc" -eq 0 ] || [ "$orc" -eq 35 ] || [ "$orc" -eq 60 ]; then
    log_json "{\"ts\":\"$(now)\",\"probe\":\"orport\",\"ok\":true,\"sec\":$elapsed,\"detail\":\"curl_exit=$orc\"}"
    echo "$(now) OK  orport curl_exit=$orc ${elapsed}s"
  else
    err=$(tr '\n' ' ' </tmp/or.err | cut -c1-120 | sed 's/"/\\"/g')
    log_json "{\"ts\":\"$(now)\",\"probe\":\"orport\",\"ok\":false,\"sec\":$elapsed,\"err\":\"curl_exit=$orc $err\"}"
    echo "$(now) ERR orport curl_exit=$orc ${elapsed}s"
  fi

  probe check_tor curl -sS --max-time 45 --socks5-hostname "$SOCKS" \
    https://check.torproject.org/api/ip
  probe cf_trace curl -sS --max-time 45 --socks5-hostname "$SOCKS" \
    https://1.1.1.1/cdn-cgi/trace
  probe ddg_onion curl -sS --max-time 90 --socks5-hostname "$SOCKS" -o /dev/null -w '%{http_code}' \
    https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/

  sleep "$INTERVAL"
done
