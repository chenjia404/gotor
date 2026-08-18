#!/usr/bin/env bash
# 真实 Tor Network E2E：SOCKS5 → check.torproject.org/api/ip
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TOR_INTEGRATION_TEST=1
SOCKS_PORT="${SOCKS_PORT:-9050}"

echo "==> go test integration (real network)"
go test ./integration/... -tags=integration -v -timeout 10m -count=1

echo "==> starting gotor client"
go run ./cmd/tor-client -socks-port "$SOCKS_PORT" &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> waiting for SOCKS ${SOCKS_PORT}"
for i in $(seq 1 90); do
  if curl -fsS --max-time 2 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://check.torproject.org/api/ip >/tmp/gotor-check.json 2>/dev/null; then
    cat /tmp/gotor-check.json
    echo
    python3 - <<'PY'
import json
d=json.load(open("/tmp/gotor-check.json"))
assert d.get("IsTor") is True, d
assert d.get("IP"), d
print("IsTor=true IP=%s" % d["IP"])
PY
    exit 0
  fi
  sleep 2
done

echo "E2E failed: check.torproject.org not reachable via SOCKS" >&2
exit 1
