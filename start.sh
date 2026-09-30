#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [ ! -f "$ROOT/data/credentials.json" ]; then
  echo "WARNING: No data/credentials.json — run ./scripts/setup_credentials.sh"
fi
export CYBERGUARDIAN_API_KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('api_key',''))" 2>/dev/null || true)
export CG_AGENT_KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('agent_api_key',''))" 2>/dev/null || true)
echo "Stopping old processes..."
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "agent.py" 2>/dev/null || true
sleep 1
echo "Starting Decision Service (8001)..."
(cd "$ROOT/control-plane/decision-service" && python3 -m uvicorn main:app --host 0.0.0.0 --port 8001 > /tmp/cg-decision.log 2>&1 &)
sleep 1
echo "Starting API Gateway (8080)..."
(cd "$ROOT/control-plane/api" && DECISION_SERVICE_URL=http://127.0.0.1:8001 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host 0.0.0.0 --port 8080 > /tmp/cg-api.log 2>&1 &)
sleep 2
echo "Starting NAD (8002)..."
(cd "$ROOT/control-plane/nad-processor" && API_URL=http://127.0.0.1:8080 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host 0.0.0.0 --port 8002 > /tmp/cg-nad.log 2>&1 &)
echo "Starting Dashboard (3000)..."
(cd "$ROOT/dashboard" && API_URL=http://127.0.0.1:8080 CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
  python3 -m uvicorn main:app --host 0.0.0.0 --port 3000 > /tmp/cg-dashboard.log 2>&1 &)
sleep 1
echo "Starting Agent..."
(cd "$ROOT" && nohup env CYBERGUARDIAN_API=http://127.0.0.1:8080 CG_CONTROLLER_URL=http://127.0.0.1:8080 \
  CYBERGUARDIAN_API_KEY="${CG_AGENT_KEY:-$CYBERGUARDIAN_API_KEY}" \
  python3 -u agents/linux-ebpf/agent.py --interval 60 > /tmp/cg-agent.log 2>&1 &)
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "============================================"
echo " CyberGuardian started"
echo "============================================"
echo "Dashboard : http://${IP:-127.0.0.1}:3000"
echo "API       : http://127.0.0.1:8080"
echo "Logs      : /tmp/cg-*.log"
echo "Stop      : $ROOT/stop.sh"
echo "============================================"
