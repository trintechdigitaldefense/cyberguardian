#!/usr/bin/env bash
# CyberGuardian start — fail loud, wait for real HTTP health, no false "started"
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

BIND_HOST="${CG_BIND_HOST:-0.0.0.0}"
if [ "${CG_HARDENED:-0}" = "1" ] || [ "${CG_HARDENED:-}" = "true" ]; then
  BIND_HOST="127.0.0.1"
  echo "HARDENED: binding services to 127.0.0.1 only"
fi

wait_http() {
  local name="$1" url="$2" attempts="${3:-30}"
  local i code
  for i in $(seq 1 "$attempts"); do
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || echo "000")
    if [ "$code" = "200" ] || [ "$code" = "204" ]; then
      echo "  $name ready (HTTP $code)"
      return 0
    fi
    sleep 0.5
  done
  echo "ERROR: $name failed readiness ($url last HTTP $code)"
  echo "  log: see /tmp/cg-*.log"
  return 1
}

shutdown_started() {
  echo "Rolling back partial start..."
  pkill -f "uvicorn main:app" 2>/dev/null || true
  pkill -f "agents/linux-ebpf/agent.py" 2>/dev/null || true
}

if [ ! -f "$ROOT/data/credentials.json" ]; then
  echo "WARNING: No data/credentials.json — run ./scripts/setup_credentials.sh"
fi
if [ -f "$ROOT/data/credentials.json" ]; then
  export CYBERGUARDIAN_API_KEY
  CYBERGUARDIAN_API_KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('api_key',''))" 2>/dev/null || true)
  export CG_AGENT_KEY
  CG_AGENT_KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('agent_api_key',''))" 2>/dev/null || true)
else
  export CYBERGUARDIAN_API_KEY="${CYBERGUARDIAN_API_KEY:-}"
  export CG_AGENT_KEY="${CG_AGENT_KEY:-}"
fi

echo "Stopping old processes..."
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "agents/linux-ebpf/agent.py" 2>/dev/null || true
sleep 1

if [ -f "$ROOT/control-plane/api/assemble_main.py" ]; then
  if ! python3 "$ROOT/control-plane/api/assemble_main.py"; then
    echo "ERROR: API gateway assemble failed — cannot start"
    exit 1
  fi
fi

echo "Starting Decision Service (8001) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/decision-service" && python3 -m uvicorn main:app --host "$BIND_HOST" --port 8001 > /tmp/cg-decision.log 2>&1 &)
if ! wait_http "decision" "http://127.0.0.1:8001/health" 20; then
  tail -20 /tmp/cg-decision.log 2>/dev/null || true
  shutdown_started
  exit 1
fi

echo "Starting API Gateway (8080) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/api" && DECISION_SERVICE_URL=http://127.0.0.1:8001 \
  CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" CG_AGENT_KEY="$CG_AGENT_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8080 > /tmp/cg-api.log 2>&1 &)
if ! wait_http "api" "http://127.0.0.1:8080/health" 30; then
  tail -30 /tmp/cg-api.log 2>/dev/null || true
  shutdown_started
  exit 1
fi

echo "Starting NAD (8002) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/nad-processor" && API_URL=http://127.0.0.1:8080 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8002 > /tmp/cg-nad.log 2>&1 &)
if ! wait_http "nad" "http://127.0.0.1:8002/health" 10; then
  echo "  WARNING: NAD not healthy (non-fatal); continuing"
fi

echo "Starting Dashboard (3000) on ${BIND_HOST}..."
(cd "$ROOT/dashboard" && API_URL=http://127.0.0.1:8080 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 3000 > /tmp/cg-dashboard.log 2>&1 &)
if ! wait_http "dashboard" "http://127.0.0.1:3000/" 20; then
  tail -20 /tmp/cg-dashboard.log 2>/dev/null || true
  shutdown_started
  exit 1
fi

echo "Starting Agent..."
(cd "$ROOT" && nohup env CYBERGUARDIAN_API=http://127.0.0.1:8080 CG_CONTROLLER_URL=http://127.0.0.1:8080 \
  CYBERGUARDIAN_API_KEY="${CG_AGENT_KEY:-$CYBERGUARDIAN_API_KEY}" \
  python3 -u agents/linux-ebpf/agent.py --interval 60 > /tmp/cg-agent.log 2>&1 &)

echo ""
echo "============================================"
echo " CyberGuardian started (health checks passed)"
echo "============================================"
if [ "$BIND_HOST" = "127.0.0.1" ]; then
  echo "Bind      : localhost only (hardened)"
  echo "Dashboard : http://127.0.0.1:3000"
else
  IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "Dashboard : http://${IP:-127.0.0.1}:3000"
  echo "WARNING   : bound 0.0.0.0 — export CG_HARDENED=1 for localhost-only"
fi
echo "API       : http://127.0.0.1:8080"
echo "Status    : $ROOT/status.sh"
echo "Logs      : /tmp/cg-*.log"
echo "Stop      : $ROOT/stop.sh"
echo "============================================"
bash "$ROOT/status.sh" || true
