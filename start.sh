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

read_credential() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get(sys.argv[2], ""))' \
    "$ROOT/data/credentials.json" "$1" 2>/dev/null || true
}

if [ ! -f "$ROOT/data/credentials.json" ]; then
  echo "WARNING: No data/credentials.json — run ./scripts/setup_credentials.sh"
fi
CYBERGUARDIAN_API_KEY="${CYBERGUARDIAN_API_KEY:-}"
CG_AGENT_KEY="${CG_AGENT_KEY:-}"
CG_DASHBOARD_API_KEY="${CG_DASHBOARD_API_KEY:-}"
CG_NAD_API_KEY="${CG_NAD_API_KEY:-}"
CG_OPERATOR_ASSERTION_SECRET="${CG_OPERATOR_ASSERTION_SECRET:-}"
DECISION_SERVICE_API_KEY="${DECISION_SERVICE_API_KEY:-}"
if [ -f "$ROOT/data/credentials.json" ]; then
  CYBERGUARDIAN_API_KEY="${CYBERGUARDIAN_API_KEY:-$(read_credential api_key)}"
  CG_AGENT_KEY="${CG_AGENT_KEY:-$(read_credential agent_api_key)}"
  CG_DASHBOARD_API_KEY="${CG_DASHBOARD_API_KEY:-$(read_credential dashboard_api_key)}"
  CG_NAD_API_KEY="${CG_NAD_API_KEY:-$(read_credential nad_api_key)}"
  CG_OPERATOR_ASSERTION_SECRET="${CG_OPERATOR_ASSERTION_SECRET:-$(read_credential operator_assertion_secret)}"
  DECISION_SERVICE_API_KEY="${DECISION_SERVICE_API_KEY:-$(read_credential decision_service_api_key)}"
fi
export CYBERGUARDIAN_API_KEY CG_AGENT_KEY CG_DASHBOARD_API_KEY CG_NAD_API_KEY
export CG_OPERATOR_ASSERTION_SECRET DECISION_SERVICE_API_KEY

STRICT_AGENT_MODE=0
case "${CG_PRODUCTION:-}" in 1|true|TRUE|yes|YES|on|ON) STRICT_AGENT_MODE=1 ;; esac
case "${CG_REQUIRE_AGENT_IDENTITY:-}" in 1|true|TRUE|yes|YES|on|ON) STRICT_AGENT_MODE=1 ;; esac
if [ "$STRICT_AGENT_MODE" = "0" ] && [ -f "$ROOT/data/credentials.json" ]; then
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("require_agent_identity") else 1)' "$ROOT/data/credentials.json" 2>/dev/null; then
    STRICT_AGENT_MODE=1
  fi
fi
if [ "$STRICT_AGENT_MODE" = "1" ]; then
  export CG_PRODUCTION=1 CG_REQUIRE_AGENT_IDENTITY=1
  if ! python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ.get("CG_CREDENTIALS_PATH", "data/credentials.json"))
try:
    stored = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, ValueError) as exc:
    raise SystemExit(f"production credentials are unavailable: {exc}")
names = (
    "CYBERGUARDIAN_API_KEY",
    "CG_DASHBOARD_API_KEY",
    "CG_NAD_API_KEY",
    "CG_OPERATOR_ASSERTION_SECRET",
    "DECISION_SERVICE_API_KEY",
)
values = [os.environ.get(name, "").strip() for name in names]
if not values[0] or values[0] != str(stored.get("api_key") or ""):
    raise SystemExit("administrator API key must match data/credentials.json")
if any(len(value.encode("utf-8")) < 32 for value in values):
    raise SystemExit("all five production service credentials/secrets must be at least 32 bytes")
if len(set(values)) != len(values):
    raise SystemExit("administrator, dashboard, NAD, operator and decision secrets must all be unique")
PY
  then
    echo "ERROR: production service credentials are incomplete or invalid."
    echo "Run ./scripts/setup_credentials.sh and configure the generated values securely."
    exit 1
  fi
fi

# Development fallback keys are deliberately confined to non-production startup.
DASHBOARD_PROCESS_KEY="${CG_DASHBOARD_API_KEY:-$CYBERGUARDIAN_API_KEY}"
NAD_PROCESS_KEY="${CG_NAD_API_KEY:-$CYBERGUARDIAN_API_KEY}"

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
(cd "$ROOT/control-plane/decision-service" && \
  CG_PRODUCTION="${CG_PRODUCTION:-0}" DECISION_SERVICE_API_KEY="$DECISION_SERVICE_API_KEY" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8001 > /tmp/cg-decision.log 2>&1 &)
if ! wait_http "decision" "http://127.0.0.1:8001/health" 20; then
  tail -20 /tmp/cg-decision.log 2>/dev/null || true
  shutdown_started
  exit 1
fi

echo "Starting API Gateway (8080) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/api" && DECISION_SERVICE_URL=http://127.0.0.1:8001 \
  CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" CG_AGENT_KEY="$CG_AGENT_KEY" \
  CG_DASHBOARD_API_KEY="$CG_DASHBOARD_API_KEY" CG_NAD_API_KEY="$CG_NAD_API_KEY" \
  CG_OPERATOR_ASSERTION_SECRET="$CG_OPERATOR_ASSERTION_SECRET" \
  DECISION_SERVICE_API_KEY="$DECISION_SERVICE_API_KEY" \
  CG_PRODUCTION="${CG_PRODUCTION:-0}" CG_REQUIRE_AGENT_IDENTITY="${CG_REQUIRE_AGENT_IDENTITY:-0}" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8080 > /tmp/cg-api.log 2>&1 &)
if ! wait_http "api" "http://127.0.0.1:8080/health" 30; then
  tail -30 /tmp/cg-api.log 2>/dev/null || true
  shutdown_started
  exit 1
fi

echo "Starting NAD (8002) on ${BIND_HOST}..."
(cd "$ROOT/control-plane/nad-processor" && API_URL=http://127.0.0.1:8080 \
  CG_NAD_API_KEY="$NAD_PROCESS_KEY" CG_PRODUCTION="${CG_PRODUCTION:-0}" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 8002 > /tmp/cg-nad.log 2>&1 &)
if ! wait_http "nad" "http://127.0.0.1:8002/health" 10; then
  echo "  WARNING: NAD not healthy (non-fatal); continuing"
fi

echo "Starting Dashboard (3000) on ${BIND_HOST}..."
(cd "$ROOT/dashboard" && API_URL=http://127.0.0.1:8080 \
  CG_DASHBOARD_API_KEY="$DASHBOARD_PROCESS_KEY" \
  CG_OPERATOR_ASSERTION_SECRET="$CG_OPERATOR_ASSERTION_SECRET" \
  CG_PRODUCTION="${CG_PRODUCTION:-0}" \
  python3 -m uvicorn main:app --host "$BIND_HOST" --port 3000 > /tmp/cg-dashboard.log 2>&1 &)
# / redirects unauthenticated users to /login (HTTP 303); use the public
# health endpoint so readiness checks process availability, not login state.
if ! wait_http "dashboard" "http://127.0.0.1:3000/health" 20; then
  tail -20 /tmp/cg-dashboard.log 2>/dev/null || true
  shutdown_started
  exit 1
fi

if [ "${CG_DISABLE_LOCAL_AGENT:-0}" = "1" ]; then
  echo "Local agent auto-start disabled (CG_DISABLE_LOCAL_AGENT=1)."
elif [ "$STRICT_AGENT_MODE" = "1" ]; then
  AGENT_ENV_FILE="${CG_AGENT_ENV_FILE:-}"
  if [ -z "$AGENT_ENV_FILE" ]; then
    echo "Production identity enforcement is enabled; skipping bootstrap agent."
    echo "Enroll this device and set CG_AGENT_ENV_FILE to its protected agent environment file."
  else
    case "$AGENT_ENV_FILE" in /*) ;; *) AGENT_ENV_FILE="$ROOT/$AGENT_ENV_FILE" ;; esac
    if [ ! -f "$AGENT_ENV_FILE" ]; then
      echo "WARNING: enrolled agent environment file not found; local agent was not started."
    elif ! python3 -c 'import os,stat,sys; s=os.stat(sys.argv[1]); sys.exit(0 if stat.S_ISREG(s.st_mode) and not (stat.S_IMODE(s.st_mode) & 0o077) else 1)' "$AGENT_ENV_FILE"; then
      echo "WARNING: agent environment file must be a regular file with no group/other permissions (0400 or 0600); local agent was not started."
    else
      echo "Starting enrolled local agent..."
      (
        set -a
        . "$AGENT_ENV_FILE"
        set +a
        : "${CYBERGUARDIAN_ASSET_ID:?missing CYBERGUARDIAN_ASSET_ID}"
        : "${CYBERGUARDIAN_TENANT:?missing CYBERGUARDIAN_TENANT}"
        : "${CYBERGUARDIAN_API_KEY:?missing per-agent CYBERGUARDIAN_API_KEY}"
        : "${CG_AGENT_IDENTITY_SECRET:?missing CG_AGENT_IDENTITY_SECRET}"
        : "${CG_COMMAND_SIGNING_SECRET:?missing CG_COMMAND_SIGNING_SECRET}"
        export CG_REQUIRE_AGENT_IDENTITY=1 CG_REQUIRE_COMMAND_SIG=1
        export CYBERGUARDIAN_API=http://127.0.0.1:8080 CG_CONTROLLER_URL=http://127.0.0.1:8080
        exec nohup python3 -u agents/linux-ebpf/agent.py --interval 60
      ) > /tmp/cg-agent.log 2>&1 &
    fi
  fi
else
  echo "Starting local development agent (bootstrap credentials; non-production only)..."
  (cd "$ROOT" && nohup env CYBERGUARDIAN_API=http://127.0.0.1:8080 CG_CONTROLLER_URL=http://127.0.0.1:8080 \
    CYBERGUARDIAN_API_KEY="${CG_AGENT_KEY:-$CYBERGUARDIAN_API_KEY}" \
    python3 -u agents/linux-ebpf/agent.py --interval 60 > /tmp/cg-agent.log 2>&1 &)
fi

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
