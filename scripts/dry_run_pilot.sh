#!/usr/bin/env bash
# Synthetic lab dry-run. Credentials are read in-process, never echoed or
# placed in curl command-line arguments.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CG_DATA_DIR="${CG_DATA_DIR:-$ROOT/data}"
API="${CG_API:-http://127.0.0.1:8080}"
TENANT_ID="${CG_TENANT_ID:-default}"
if [ -z "$TENANT_ID" ]; then
  echo "CG_TENANT_ID must identify the tenant for this pilot." >&2
  exit 1
fi
export CG_TENANT_ID="$TENANT_ID"

echo "=== CyberGuardian Synthetic Dry-Run ==="
python3 - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

api = os.environ.get("CG_API", "http://127.0.0.1:8080").rstrip("/")
credentials_path = Path(os.environ["CG_DATA_DIR"]) / "credentials.json"
try:
    credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, ValueError) as exc:
    raise SystemExit(f"Cannot read protected credentials file: {exc}")
key = credentials.get("api_key")
if not isinstance(key, str) or not key:
    raise SystemExit("Administrator API key is missing from credentials file")

def call(label, path, method="GET", payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {
        "X-API-Key": key,
        "X-Tenant-ID": os.environ.get("CG_TENANT_ID", "default"),
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(api + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            raw = response.read()
            try:
                result = json.loads(raw)
            except (UnicodeError, ValueError):
                result = raw.decode("utf-8", errors="replace")
            print(f"{label}: HTTP {response.status}")
            print(json.dumps(result, indent=2, sort_keys=True) if isinstance(result, (dict, list)) else result)
            return result
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"{label}: HTTP {exc.code}: {detail}", file=sys.stderr)
        raise SystemExit(1)
    except OSError as exc:
        print(f"{label}: request failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

health = call("Health", "/health")
mode = call("Set Client Mode ON", "/v1/client-mode", "POST", {"client_mode": True})
remembered = call(
    "Create synthetic dry-run issue",
    "/v1/issues/remember",
    "POST",
    {
        "title": "DRY-RUN synthetic credential-access simulation",
        "asset_id": "linux-localhost",
        "severity": "high",
        "tags": ["credential_access", "dry-run", "synthetic"],
        "indicators": {"pid": "4242", "source": "owner-pilot-validation"},
    },
)
remediation = call("Attempt gated auto-remediation", "/v1/issues/auto-remediate", "POST")

# Fail if the API explicitly reports that Client Mode is off. Keep the full
# response visible for the operator to verify the human gate's blocked result.
if isinstance(mode, dict) and mode.get("client_mode") is False:
    raise SystemExit("Safety check failed: API reports Client Mode OFF")
print("Review the auto-remediation response: it must remain blocked pending human approval.")
print("No disruptive action should be approved or executed during this dry-run.")
PY
echo "=== Synthetic dry-run requests completed ==="
