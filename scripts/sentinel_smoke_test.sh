#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${CYBERGUARDIAN_API:-http://127.0.0.1:8080}"
KEY="${CYBERGUARDIAN_API_KEY:-}"
if [ -z "$KEY" ] && [ -f "$ROOT/data/credentials.json" ]; then
  KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('api_key',''))")
fi
SENTINEL_URL="${SENTINEL_URL:-http://127.0.0.1:8787}"
echo "=== CyberGuardian → Sentinel bridge smoke test ==="
echo "API=$API  SENTINEL_URL=$SENTINEL_URL"
echo ""
echo "1) Enable bridge on CyberGuardian"
curl -sS -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d "{\"enabled\":true,\"sentinel_url\":\"$SENTINEL_URL\",\"push_on_approve\":true}" \
  "$API/v1/sentinel/config" | python3 -m json.tool || true
echo ""
echo "2) Bridge status"
curl -sS -H "X-API-Key: $KEY" "$API/v1/sentinel" | python3 -m json.tool || true
echo ""
echo "3) Direct Sentinel /health (if running)"
if curl -sS -m 3 "$SENTINEL_URL/health" 2>/dev/null; then
  echo ""
  echo "   Sentinel reachable"
else
  echo "   Sentinel not reachable at $SENTINEL_URL — bridge soft-fails until it is up"
fi
echo ""
echo "Done. Review step 2 'reachable' field."
