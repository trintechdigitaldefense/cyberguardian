#!/usr/bin/env bash
# First-run credential setup for CyberGuardian (writes data/credentials.json mode 600).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/data"
chmod 700 "$ROOT/data"

python3 - "$ROOT" << 'PY'
import base64, hashlib, json, os, secrets, sys, getpass, tempfile
from pathlib import Path

root = Path(sys.argv[1])
# The heredoc supplies this script on stdin; read interactive answers from the controlling terminal.
try:
    sys.stdin = open('/dev/tty', 'r', encoding='utf-8')
except OSError:
    raise SystemExit('ERROR: credential setup requires an interactive terminal (/dev/tty). Run it directly in your terminal, not through a pipe or background job.')
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

salt = secrets.token_bytes(16)
iterations = 310_000
digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
password_hash = "pbkdf2_sha256" + "$" + str(iterations) + "$" + salt_b64 + "$" + digest_b64

api_key = input("Admin API key (empty = auto-generate): ").strip()
if not api_key:
    api_key = "cg_" + secrets.token_urlsafe(32)
agent_key = existing.get("agent_api_key") or ("cg_agent_" + secrets.token_urlsafe(24))
cred = dict(existing)
cred.update({
    "admin_user": user,
    "admin_password_hash": password_hash,
    "api_key": api_key,
    "agent_api_key": agent_key,
})
cred.pop("admin_password", None)

fd, temp_name = tempfile.mkstemp(prefix=".credentials.", dir=str(data))
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(cred, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_name, path)
    path.chmod(0o600)
finally:
    if os.path.exists(temp_name):
        os.unlink(temp_name)

print(f"Saved hashed credentials: {path}")
print(f"Admin API key (save this): {api_key}")
print(f"Agent API key (save this): {agent_key}")
print("Password is stored as a PBKDF2 hash, not plaintext.")
print("Done. Keep keys secret. Never commit credentials.json.")
PY
