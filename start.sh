#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

BIND_HOST="${CG_BIND_HOST:-0.0.0.0}"
if [ "${CG_HARDENED:-0}" = "1" ] || [ "${CG_HARDENED:-}" = "true" ]; then
  BIND_HOST="127.0.0.1"
  echo "HARDENED: binding services to 127.0.0.1 only (set CG_BIND_HOST to override)"
fi

if [ ! -f "$ROOT/data/credentials.json" ]; then
  echo "WARNING: No data/credentials.json — run ./scripts/setup_credentials.sh"
fi
if [ -f "$ROOT/data/credentials.json" ]; then
  export CYBERGUARDIAN_API_KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('api_key',''))" 2>/dev/null || true)
  export CG_AGENT_KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('agent_api_key',''))" 2>/dev/null || true)
else
  export CYBERGUARDIAN_API_KEY="${CYBERGUARDIAN_API_KEY:-}"
  export CG_AGENT_KEY="${CG_AGENT_KEY:-}"
fi

echo "Stopping old processes..."
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "agents/linux-ebpf/agent.py" 2>/dev/null || true
sleep 1

echo "Starting Decision Service (8001) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/decision-service" && python3 -m uvicorn main:app --host "$BIND_HOST" --port 8001 > /tmp/cg-decision.log 2>&1 &)
sleep 1
echo "Starting API Gateway (8080) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/api" && DECISION_SERVICE_URL=http://127.0.0.1:8001 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8080 > /tmp/cg-api.log 2>&1 &)
sleep 2
echo "Starting NAD (8002) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/nad-processor" && API_URL=http://127.0.0.1:8080 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8002 > /tmp/cg-nad.log 2>&1 &)
echo "Starting Dashboard (3000) on ${BIND_HOST}..."
(cd "$ROOT/dashboard" && API_URL=http://127.0.0.1:8080 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 3000 > /tmp/cg-dashboard.log 2>&1 &)
sleep 1
echo "Starting Agent..."
(cd "$ROOT" && nohup env CYBERGUARDIAN_API=http://127.0.0.1:8080 CG_CONTROLLER_URL=http://127.0.0.1:8080 \
  CYBERGUARDIAN_API_KEY="${CG_AGENT_KEY:-$CYBERGUARDIAN_API_KEY}" \
  python3 -u agents/linux-ebpf/agent.py --interval 60 > /tmp/cg-agent.log 2>&1 &)

echo ""
echo "============================================"
echo " CyberGuardian started"
echo "============================================"
if [ "$BIND_HOST" = "127.0.0.1" ]; then
  echo "Bind      : localhost only (hardened)"
  echo "Dashboard : http://127.0.0.1:3000"
  echo "Tip       : ssh -L 3000:127.0.0.1:3000 user@host"
else
  IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "Dashboard : http://${IP:-127.0.0.1}:3000"
  echo "WARNING   : bound 0.0.0.0 — do not expose to public internet"
  echo "           export CG_HARDENED=1 for localhost-only"
fi
echo "API       : http://127.0.0.1:8080"
echo "Logs      : /tmp/cg-*.log"
echo "Docs      : docs/HARDENING.md"
echo "Stop      : $ROOT/stop.sh"
echo "============================================"
