#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root for systemd install (needed for isolate/block)."
  exit 1
fi
mkdir -p /opt/cyberguardian /etc/cyberguardian
rsync -a "$ROOT/agents" /opt/cyberguardian/
if [ -f /etc/cyberguardian/agent.env ]; then
  echo "Using existing /etc/cyberguardian/agent.env"
else
  cp "$ROOT/agents/linux-ebpf/agent.env.example" /etc/cyberguardian/agent.env
  chmod 600 /etc/cyberguardian/agent.env
  echo "Edit /etc/cyberguardian/agent.env with controller URL and agent key"
fi
cp "$ROOT/agents/linux-ebpf/cyberguardian-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable cyberguardian-agent.service
echo "Start with: systemctl start cyberguardian-agent"
echo "Logs: journalctl -u cyberguardian-agent -f"
