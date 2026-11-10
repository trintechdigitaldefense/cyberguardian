#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
RUNDIR="$ROOT/data/run"
echo "Stopping CyberGuardian..."
for name in agent dashboard nad api decision; do
  pf="$RUNDIR/${name}.pid"
  if [ -f "$pf" ]; then
    pid=$(cat "$pf" 2>/dev/null || true)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      cmd=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null || true)
      case "$cmd" in
        *uvicorn*|*agent.py*|*cyberguardian*|*control-plane*)
          kill "$pid" 2>/dev/null || true
          sleep 0.2
          kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
          ;;
      esac
    fi
    rm -f "$pf"
  fi
done
echo "Stopped."
