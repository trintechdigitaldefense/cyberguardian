#!/usr/bin/env bash
# First-run credential setup for CyberGuardian (writes data/credentials.json mode 600)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/data"
export CG_ROOT="$ROOT"

python3 - "$ROOT" << 'PY'
import json, secrets, sys, getpass
from pathlib import Path

root = Path(sys.argv[1])
data = root / "data"
data.mkdir(parents=True, exist_ok=True)
path = data / "credentials.json"
existing = {}
if path.exists():
    try:
        existing = json.loads(path.read_text())
    except Exception:
        pass

print("============================================")
print(" CyberGuardian first-run credential setup")
print("============================================")
user = input(f"Admin username [{existing.get('admin_user', 'cyberguardian')}]: ").strip() or existing.get("admin_user") or "cyberguardian"
while True:
    pw = getpass.getpass("Admin password (min 10 chars): ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("Passwords do not match.")
        continue
    if len(pw) < 10:
        print("Password too short (min 10).")
        continue
    break
api_key = input("Admin API key (empty = auto-generate): ").strip()
if not api_key:
    api_key = "cg_" + secrets.token_urlsafe(32)
agent_key = existing.get("agent_api_key") or ("cg_agent_" + secrets.token_urlsafe(24))
cred = {
    "admin_user": user,
    "admin_password": pw,
    "api_key": api_key,
    "agent_api_key": agent_key,
}
path.write_text(json.dumps(cred, indent=2))
path.chmod(0o600)
print(f"Saved: {path}")
print(f"Admin API key (save this): {api_key}")
print(f"Agent API key (save this): {agent_key}")
print("Done. Keep keys secret. Never commit credentials.json.")
PY
