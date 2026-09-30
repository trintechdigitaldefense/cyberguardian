#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ok=0; fail=0
check() { if curl -s --max-time 2 "$1" | grep -q ok; then echo "  [OK] $2"; ok=$((ok+1)); else echo "  [FAIL] $2"; fail=$((fail+1)); fi; }
echo "============================================"
echo " CyberGuardian Client Pilot Health Check"
echo "============================================"
if [ -f "$ROOT/data/credentials.json" ]; then echo "  [OK] credentials present"; ok=$((ok+1)); else echo "  [FAIL] credentials"; fail=$((fail+1)); fi
check http://127.0.0.1:8001/health "Decision service"
check http://127.0.0.1:8080/health "API gateway"
check http://127.0.0.1:3000/health "Dashboard"
echo "============================================"
echo " Passed: $ok  Failed: $fail"
if [ "$fail" -eq 0 ]; then echo " Pilot gate: GREEN"; else echo " Pilot gate: YELLOW/RED"; fi
echo "============================================"
