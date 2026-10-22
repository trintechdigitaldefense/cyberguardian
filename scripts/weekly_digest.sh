#!/usr/bin/env bash
# Fetch weekly operator digest and save under data/reports/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
API="${CG_API:-http://127.0.0.1:8080}"
KEY=$(python3 -c "import json;print(json.load(open('$ROOT/data/credentials.json')).get('api_key',''))" 2>/dev/null || true)
if [ -z "$KEY" ]; then
  echo "No admin api_key in data/credentials.json"
  exit 1
fi
mkdir -p data/reports
STAMP=$(date -u +%Y%m%d)
OUT="data/reports/weekly_${STAMP}.txt"
curl -sf --max-time 15 -H "X-API-Key: $KEY" "$API/v1/reports/weekly" -o "$OUT"
echo "Wrote $OUT"
cat "$OUT"
if [ -n "${CG_DIGEST_EMAIL:-}" ] && command -v mail >/dev/null 2>&1; then
  mail -s "CyberGuardian weekly digest $STAMP" "$CG_DIGEST_EMAIL" < "$OUT"
  echo "Emailed to $CG_DIGEST_EMAIL"
fi
