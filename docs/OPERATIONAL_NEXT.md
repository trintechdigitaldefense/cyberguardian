# Operational next steps (v1.5.1)

Do this in order. Feature work waits until the host is green.

## A. Full `main.py` on the pilot host

GitHub may still have a thin/broken loader. Source of truth is the ~52KB file that starts with `CyberGuardian API Gateway v1.4.0-tier3`.

```bash
cd /root/~/cyberguardian   # adjust path
cp control-plane/api/main.py control-plane/api/main.py.bak 2>/dev/null || true
rm -rf control-plane/api/gateway_parts control-plane/api/main_b64
# scp full main.py into control-plane/api/main.py
wc -c control-plane/api/main.py   # expect ~50KB+
head -3 control-plane/api/main.py
```

## B. Credentials (local only — never git push)

```bash
python3 << 'PY'
import json, secrets
from pathlib import Path
p = Path("data"); p.mkdir(parents=True, exist_ok=True)
pw = secrets.token_urlsafe(12)
cred = {
  "admin_user": "cyberguardian",
  "admin_password": pw,
  "api_key": "cg_" + secrets.token_urlsafe(32),
  "agent_api_key": "cg_agent_" + secrets.token_urlsafe(24),
}
path = p / "credentials.json"
path.write_text(json.dumps(cred, indent=2))
path.chmod(0o600)
print("Admin password:", pw)
print("Admin API key:", cred["api_key"])
print("Agent API key:", cred["agent_api_key"])
PY
```

## C. Health + dashboard

```bash
bash stop.sh && bash start.sh && sleep 2
curl -sS http://127.0.0.1:8080/health
curl -sS -o /dev/null -w "dashboard:%{http_code}\n" http://127.0.0.1:3000/
```

Open **http://127.0.0.1:3000**

## D. Push full main.py from build machine

```bash
git add control-plane/api/main.py
git commit -m "v1.5.1: full API gateway main.py"
git push origin main
```

## E. Supervised pilot proof

Agent + Client Mode ON → detect → approve → contain → audit → weekly PDF.
