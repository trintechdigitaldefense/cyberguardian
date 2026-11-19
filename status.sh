#!/usr/bin/env bash
# CyberGuardian component status — healthy | unhealthy | degraded | stopped
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

check_http() {
  local name="$1" url="$2"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
  if [ "$code" = "200" ] || [ "$code" = "204" ]; then
    echo "  $name: healthy (HTTP $code)"
    return 0
  elif [ "$code" = "000" ]; then
    echo "  $name: stopped (no response)"
    return 2
  else
    echo "  $name: unhealthy (HTTP $code)"
    return 1
  fi
}

proc_hint() {
  local pattern="$1"
  if pgrep -f "$pattern" >/dev/null 2>&1; then
    echo "running"
  else
    echo "not running"
  fi
}

echo "============================================"
echo " CyberGuardian status"
echo "============================================"
echo "Root: $ROOT"
echo ""
echo "Processes:"
echo "  decision-service : $(proc_hint 'uvicorn main:app')"
echo "  agent            : $(proc_hint 'agents/linux-ebpf/agent.py')"
echo ""
echo "HTTP health:"
fail=0
check_http "decision (8001)" "http://127.0.0.1:8001/health" || fail=$((fail+1))
check_http "api      (8080)" "http://127.0.0.1:8080/health" || fail=$((fail+1))
# The dashboard root redirects unauthenticated users to /login (HTTP 303); probe its public health endpoint instead.
check_http "dashboard(3000)" "http://127.0.0.1:3000/health" || fail=$((fail+1))
echo ""
if [ ! -f "$ROOT/data/credentials.json" ]; then
  echo "Credentials: MISSING"
  fail=$((fail+1))
else
  echo "Credentials: present"
fi
echo ""
if [ "$fail" -eq 0 ]; then
  echo "Overall: HEALTHY"
  exit 0
elif [ "$fail" -le 2 ]; then
  echo "Overall: DEGRADED ($fail issue(s))"
  exit 1
else
  echo "Overall: UNHEALTHY ($fail issue(s))"
  exit 2
fi
