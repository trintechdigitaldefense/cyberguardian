#!/usr/bin/env bash
echo "Stopping CyberGuardian..."
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "agents/linux-ebpf/agent.py" 2>/dev/null || true
sleep 1
echo "Stopped."
