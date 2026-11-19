#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ok=0
fail=0
check() {
  local url="$1" label="$2"
  local -a headers=()
  if [[ "$url" == *":8080/health" && -n "${CG_PILOT_RUN_ID:-}" ]]; then
    headers=(-H "X-CG-Pilot-Run-ID: $CG_PILOT_RUN_ID" -H "X-Tenant-ID: ${CG_TENANT_ID:-default}")
  fi
  if curl -fsS --max-time 3 "${headers[@]}" "$url" | grep -qi "ok"; then
    echo "  [OK] $label"
    ok=$((ok+1))
  else
    echo "  [FAIL] $label"
    fail=$((fail+1))
  fi
}
echo "============================================"
echo " CyberGuardian Client Pilot Health Check"
echo "============================================"
if [ -f "${CG_DATA_DIR:-$ROOT/data}/credentials.json" ]; then
  echo "  [OK] credentials file present"
  ok=$((ok+1))
else
  echo "  [FAIL] credentials file missing"
  fail=$((fail+1))
fi
check http://127.0.0.1:8001/health "Decision service"
check http://127.0.0.1:8080/health "API gateway"
check http://127.0.0.1:3000/health "Dashboard"
echo "============================================"
echo " Passed: $ok  Failed: $fail"
if [ "$fail" -eq 0 ]; then
  echo " Health result: PASS"
else
  echo " Health result: FAIL — stop pilot and inspect service logs"
fi
echo "============================================"
[ "$fail" -eq 0 ]
