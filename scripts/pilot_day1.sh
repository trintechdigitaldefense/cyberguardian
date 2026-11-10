#!/usr/bin/env bash
# CyberGuardian owner-operated pilot smoke pack.
# Never prints or places credentials in shell command-line arguments.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo " CyberGuardian R4 Owner Pilot Smoke Pack"
echo "=============================================="
echo "Scope: local synthetic lab only; no client networks."

if [ ! -f "${CG_DATA_DIR:-$ROOT/data}/credentials.json" ]; then
  echo "[1/5] Creating local credentials..."
  bash scripts/setup_credentials.sh
else
  echo "[1/5] Local credentials file present"
fi

# Keep all standalone services on loopback and do not start a bootstrap agent.
export CG_HARDENED=1
export CG_DISABLE_LOCAL_AGENT=1
API="${CG_API:-http://127.0.0.1:8080}"

echo "[2/5] Checking API health..."
if ! curl -fsS --max-time 3 "$API/health" >/dev/null 2>&1; then
  echo "       API not running; starting hardened local services..."
  ./start.sh
fi

echo "[3/5] Verifying service health..."
bash scripts/client_health.sh

echo "[4/5] Running synthetic dry-run..."
CG_API="$API" bash scripts/dry_run_pilot.sh

echo "[5/5] Retrieving pilot scorecard (credentials stay inside Python)..."
CG_API="$API" python3 - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

api = os.environ.get("CG_API", "http://127.0.0.1:8080").rstrip("/")
data_dir = Path(os.environ.get("CG_DATA_DIR", "data"))
credentials = json.loads((data_dir / "credentials.json").read_text(encoding="utf-8"))
key = credentials.get("api_key")
if not isinstance(key, str) or not key:
    raise SystemExit("Missing administrator API key in protected credentials file")
request = urllib.request.Request(
    api + "/v1/pilot/scorecard",
    headers={"X-API-Key": key, "Accept": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=8) as response:
        payload = response.read()
        print(json.dumps(json.loads(payload), indent=2, sort_keys=True))
except urllib.error.HTTPError as exc:
    print(f"Scorecard request failed: HTTP {exc.code}", file=sys.stderr)
    raise SystemExit(1)
except (OSError, ValueError) as exc:
    print(f"Scorecard request failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY

echo "=============================================="
echo " Smoke pack completed. Review dashboard and logs."
echo " This is not R4 sign-off or client deployment approval."
echo " No agent key or service secret has been printed."
echo "=============================================="
