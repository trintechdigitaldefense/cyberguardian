#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('api_key',''))" 2>/dev/null || true)
API="${CG_API:-http://127.0.0.1:8080}"
echo "=== CyberGuardian Dry-Run ==="
echo -n "Health: "; curl -s --max-time 3 "$API/health"; echo
if [ -z "$KEY" ]; then echo "No credentials.json — run scripts/setup_credentials.sh"; exit 1; fi
echo -n "ClientMode ON: "; curl -s --max-time 5 -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"client_mode":true}' "$API/v1/client-mode"; echo
echo -n "Remember: "; curl -s --max-time 5 -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"title":"Dry-run mimikatz","asset_id":"linux-localhost","severity":"high","tags":["credential_access","dry-run"],"indicators":{"pid":"4242"}}' \
  "$API/v1/issues/remember"; echo
echo -n "AutoRemediate: "; curl -s --max-time 5 -X POST -H "X-API-Key: $KEY" "$API/v1/issues/auto-remediate"; echo
echo "=== Expect client_mode true and auto-remediate blocked ==="
