#!/usr/bin/env bash
# CyberGuardian one-click pilot pack — day-1 checklist
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo " CyberGuardian Pilot Day-1 Pack"
echo "=============================================="

if [ ! -f data/credentials.json ]; then
  echo "[1/6] Creating credentials..."
  bash scripts/setup_credentials.sh
else
  echo "[1/6] Credentials present"
fi

KEY=$(python3 -c "import json;print(json.load(open('data/credentials.json')).get('api_key',''))" 2>/dev/null || true)
AGENT_KEY=$(python3 -c "import json;print(json.load(open('data/credentials.json')).get('agent_api_key',''))" 2>/dev/null || true)
API="${CG_API:-http://127.0.0.1:8080}"

echo "[2/6] Checking API health..."
if ! curl -sf --max-time 3 "$API/health" >/dev/null 2>&1; then
  echo "       API not up — starting stack..."
  if [ -x ./start.sh ]; then
    ./start.sh || true
    sleep 3
  else
    echo "       start.sh missing — start services manually"
  fi
fi
curl -sf --max-time 5 "$API/health" && echo || { echo "API still down"; exit 1; }

echo "[3/6] Ensuring Client Mode ON..."
curl -sf --max-time 5 -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"client_mode":true}' "$API/v1/client-mode" | head -c 200
echo

echo "[4/6] Health script..."
bash scripts/client_health.sh || true
echo "[5/6] Dry-run (expect auto-remediate blocked)..."
bash scripts/dry_run_pilot.sh || true

echo "[6/6] Pilot scorecard..."
curl -sf --max-time 5 -H "X-API-Key: $KEY" "$API/v1/pilot/scorecard" | python3 -m json.tool 2>/dev/null || \
  curl -sf --max-time 5 -H "X-API-Key: $KEY" "$API/v1/pilot/scorecard"
echo

echo "=============================================="
echo " DAY-1 CHECKLIST"
echo "=============================================="
echo " [ ] Dashboard login works  →  http://127.0.0.1:3000"
echo " [ ] Client Mode shows ON"
echo " [ ] Agent registered (run agent with agent key)"
echo " [ ] Scorecard mostly green"
echo " [ ] Approve/reject a test gate item"
echo ""
echo "Agent example:"
echo "  export CYBERGUARDIAN_API=$API"
echo "  export CYBERGUARDIAN_API_KEY=\"$AGENT_KEY\""
echo "  python3 agents/linux-ebpf/agent.py --interval 30"
echo ""
echo "Approve in dashboard queues a REAL host command."
echo "Network isolate/block needs root on the agent host."
echo "=============================================="
