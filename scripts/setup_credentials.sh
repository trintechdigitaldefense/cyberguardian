#!/usr/bin/env bash
# First-run credential setup for CyberGuardian (writes data/credentials.json mode 600).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${CG_DATA_DIR:-$ROOT/data}"
case "$DATA_DIR" in /*) ;; *) DATA_DIR="$ROOT/$DATA_DIR" ;; esac
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

python3 - "$DATA_DIR" << 'PY'
import base64, hashlib, json, os, secrets, sys, getpass, tempfile
from pathlib import Path

data = Path(sys.argv[1]).expanduser()
# The heredoc supplies this script on stdin; read interactive answers from the controlling terminal.
try:
    sys.stdin = open('/dev/tty', 'r', encoding='utf-8')
except OSError:
    raise SystemExit('ERROR: credential setup requires an interactive terminal (/dev/tty). Run it directly in your terminal, not through a pipe or background job.')
data.mkdir(parents=True, exist_ok=True)
path = data / "credentials.json"
existing = {}
if path.exists():
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"ERROR: existing credentials file is unreadable; refusing to overwrite it: {exc}")
    if not isinstance(existing, dict):
        raise SystemExit("ERROR: existing credentials file has an invalid schema; refusing to overwrite it.")

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
if len(api_key.encode("utf-8")) < 32:
    raise SystemExit("ERROR: administrator API key must be at least 32 bytes; leave it blank to generate one.")
rotate_agent_key = os.environ.get("CG_ROTATE_BOOTSTRAP_AGENT_KEY", "").strip().lower() in {"1", "true", "yes"}
agent_key = existing.get("agent_api_key") or ""
if rotate_agent_key or len(agent_key.encode("utf-8")) < 32 or agent_key == api_key:
    agent_key = "cg_agent_" + secrets.token_urlsafe(32)
used = {api_key, agent_key}
service_credentials = {}
for field in (
    "dashboard_api_key",
    "nad_api_key",
    "operator_assertion_secret",
    "decision_service_api_key",
):
    value = str(existing.get(field) or "").strip()
    if len(value.encode("utf-8")) < 32 or value in used:
        value = secrets.token_urlsafe(48)
    while value in used:
        value = secrets.token_urlsafe(48)
    service_credentials[field] = value
    used.add(value)

cred = dict(existing)
cred.update({
    "admin_user": user,
    "admin_password_hash": password_hash,
    "api_key": api_key,
    "agent_api_key": agent_key,
    **service_credentials,
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
print(f"Agent API key (lab bootstrap only; save securely): {agent_key}")
if rotate_agent_key:
    print("Legacy bootstrap agent key rotated because CG_ROTATE_BOOTSTRAP_AGENT_KEY was enabled.")
print("Service credentials (save these for production deployment):")
print(f"CG_DASHBOARD_API_KEY={service_credentials['dashboard_api_key']}")
print(f"CG_NAD_API_KEY={service_credentials['nad_api_key']}")
print(f"CG_OPERATOR_ASSERTION_SECRET={service_credentials['operator_assertion_secret']}")
print(f"DECISION_SERVICE_API_KEY={service_credentials['decision_service_api_key']}")
print("Password is stored as a PBKDF2 hash, not plaintext.")
print("Done. Keep keys secret. Never commit credentials.json.")
PY
