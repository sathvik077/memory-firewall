#!/usr/bin/env bash
# Start/stop the local stack for scripted verification runs. PID-file based so that stopping it
# never relies on a process-name match (a `pkill -f` pattern can match the calling shell itself).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PIDS="$ROOT/.devstack.pids"
WEB_PORT="${MF_WEB_PORT:-5174}"
API_PORT="${MF_API_PORT:-8002}"

start() {
  stop >/dev/null 2>&1
  : > "$PIDS"
  export MF_DEV_EXPOSE_DEMO_TOKENS=1 MF_ENABLE_UNGUARDED_BASELINE=1 MF_DEV_QUIET=1
  export PYTHONPATH="$ROOT/packages/memory_firewall:$ROOT/apps/api:$ROOT"
  if python3 -c "import fastapi" 2>/dev/null; then
    python3 -m uvicorn app.main:app --app-dir apps/api --host 127.0.0.1 --port "$API_PORT" \
      > "$ROOT/.devstack-api.log" 2>&1 &
    echo $! >> "$PIDS"
    for _ in $(seq 1 40); do
      curl -fsS "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1 && break
      sleep 0.25
    done
    echo "api: FastAPI on 127.0.0.1:$API_PORT"
  else
    echo "api: FastAPI unavailable -> the dashboard server will serve /api in process"
  fi
  python3 scripts/serve_dashboard.py --port "$WEB_PORT" --api-port "$API_PORT" \
    > "$ROOT/.devstack-web.log" 2>&1 &
  echo $! >> "$PIDS"
  for _ in $(seq 1 40); do
    curl -fsS "http://127.0.0.1:$WEB_PORT/healthz" >/dev/null 2>&1 && break
    sleep 0.25
  done
  if curl -fsS "http://127.0.0.1:$WEB_PORT/healthz" >/dev/null 2>&1; then
    echo "web: http://127.0.0.1:$WEB_PORT"
  else
    echo "web: FAILED to come up; see .devstack-web.log" >&2
    tail -20 "$ROOT/.devstack-web.log" >&2
    return 1
  fi
}

stop() {
  if [ -f "$PIDS" ]; then
    while read -r pid; do
      [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
    done < "$PIDS"
    rm -f "$PIDS"
  fi
  echo "stopped"
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  *) echo "usage: $0 {start|stop|restart}" >&2; exit 2 ;;
esac
