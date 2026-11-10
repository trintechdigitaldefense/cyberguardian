#!/usr/bin/env python3
"""CyberGuardian Linux protective agent v1.5.0-strength — detect, FIM, netwatch, contain."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offline_queue import OfflineQueue
from containment import execute_command
from command_crypto import verify_command, claim_command

try:
    import fim as _fim
except ImportError:
    _fim = None
try:
    import netwatch as _net
except ImportError:
    _net = None

API = os.environ.get("CYBERGUARDIAN_API") or os.environ.get("CG_CONTROLLER_URL") or "http://127.0.0.1:8080"
KEY = os.environ.get("CYBERGUARDIAN_API_KEY") or os.environ.get("CG_AGENT_API_KEY") or ""
ASSET = os.environ.get("CYBERGUARDIAN_ASSET_ID") or f"linux-{socket.gethostname()}"
TENANT = os.environ.get("CYBERGUARDIAN_TENANT") or "default"
PROC_ROOT = Path("/proc")
VERSION = "1.5.0-strength"

queue = OfflineQueue()
baseline_names: set = set()
scan_count = 0
_net_seen: set = set()
_fim_ready = False

SUSPICIOUS = {"mimikatz", "powershell -enc", "nc.exe", "ncat", "meterpreter", "cobaltstrike"}


def cg_api_post(path: str, payload: dict, timeout: int = 10):
    url = API.rstrip("/") + path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "X-API-Key": KEY, "X-Tenant-ID": TENANT}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                return True, json.loads(body)
            except Exception:
                return True, {"raw": body}
    except Exception as e:
        try:
            queued = queue.enqueue("POST", path, payload)
            print(f"[agent] POST {path} failed — queued ({queued} pending): {e}")
        except Exception as queue_error:
            # Preserve existing unacknowledged events on overflow; never silently
            # evict old telemetry to make room for a newer record.
            print(f"[agent] POST {path} failed and offline queue rejected the event: {queue_error}")
        return False, {}


def cg_api_get(path: str, timeout: int = 10):
    url = API.rstrip("/") + path
    req = urllib.request.Request(url, headers={"X-API-Key": KEY, "X-Tenant-ID": TENANT}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                return True, json.loads(body)
            except Exception:
                return True, {"raw": body}
    except Exception as e:
        print(f"[agent] GET {path} failed: {e}")
        return False, {}


def _machine_id() -> str:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return Path(p).read_text().strip()
        except Exception:
            continue
    return ""


def _fingerprint(hostname: str, os_info: str, machine_id: str) -> str:
    return hashlib.sha256(f"{hostname}|{os_info}|{machine_id}".encode()).hexdigest()[:32]


def register():
    hostname = socket.gethostname()
    os_info = f"linux-{os.uname().release if hasattr(os, 'uname') else 'unknown'}"
    mid = _machine_id()
    fp = _fingerprint(hostname, os_info, mid)
    ts = time.time()
    secret = os.environ.get("CG_AGENT_IDENTITY_SECRET") or ""
    sig = ""
    if secret:
        msg = f"{ASSET}|{fp}|{int(ts)}".encode()
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    tags = ["linux", "smart-agent", "containment", "fim", f"v{VERSION}"]
    extra = os.environ.get("CYBERGUARDIAN_TAGS", "")
    if extra:
        tags.extend([t.strip() for t in extra.split(",") if t.strip()])
    ok, data = cg_api_post("/v1/assets/register", {
        "asset_id": ASSET, "hostname": hostname, "asset_type": "endpoint", "os": os_info,
        "tags": tags, "agent_version": VERSION, "tenant_id": TENANT,
        "machine_id": mid, "fingerprint": fp, "identity_ts": ts, "identity_sig": sig,
    })
    print("[agent] registered →", data.get("status") if isinstance(data, dict) else data)
    return ok


def heartbeat():
    # Registration carries the signed fingerprint envelope; do not send an
    # unsigned partial registration as a heartbeat.
    return register()


def _proc_start_time(pid: str) -> str:
    try:
        stat_text = (PROC_ROOT / str(pid) / "stat").read_text(encoding="utf-8")
        close = stat_text.rfind(")")
        if close < 0:
            return ""
        fields = stat_text[close + 2 :].split()
        return fields[19] if len(fields) > 19 else ""
    except (OSError, ValueError, IndexError):
        return ""


def list_processes():
    procs = []
    try:
        for pid in os.listdir(str(PROC_ROOT)):
            if not pid.isdigit():
                continue
            try:
                proc = PROC_ROOT / pid
                cmd = (proc / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
                if not cmd:
                    cmd = (proc / "comm").read_text(errors="ignore").strip()
                procs.append({"pid": pid, "cmd": cmd, "start_time": _proc_start_time(pid)})
            except Exception:
                continue
    except Exception:
        pass
    return procs

def poll_and_execute_commands():
    ok, data = cg_api_get(f"/v1/agent/commands?asset_id={ASSET}")
    if not ok or not isinstance(data, dict):
        return
    for cmd in data.get("commands") or []:
        cmd_id = str(cmd.get("id") or cmd.get("command_id") or "")
        action = str(cmd.get("action") or "")
        valid, reason = verify_command(
            cmd,
            expected_asset_id=ASSET,
            expected_tenant_id=TENANT,
        )
        if not valid:
            print(f"[agent] rejected invalid command id={cmd_id}: {reason}")
            if cmd_id:
                cg_api_post("/v1/agent/command-result", {
                    "command_id": cmd_id, "asset_id": ASSET, "action": action,
                    "target": cmd.get("target"), "ok": False,
                    "detail": f"command rejected before execution: {reason}",
                    "result": {"rejected": True, "reason": reason},
                })
            continue
        if not claim_command(cmd):
            print(f"[agent] rejected replayed command id={cmd_id}")
            cg_api_post("/v1/agent/command-result", {
                "command_id": cmd_id, "asset_id": ASSET, "action": action,
                "target": cmd.get("target"), "ok": False,
                "detail": "command replay rejected",
                "result": {"rejected": True, "reason": "replay"},
            })
            continue
        print(f"[agent] executing verified command {action} id={cmd_id}")
        result = execute_command(cmd, controller_url=API)
        cg_api_post("/v1/agent/command-result", {
            "command_id": cmd_id, "asset_id": ASSET, "action": action, "target": cmd.get("target"),
            "ok": bool(result.get("ok")), "detail": result.get("detail") or "", "result": result,
        })

def fim_scan():
    global _fim_ready
    if _fim is None:
        return
    try:
        if not _fim_ready:
            _fim.establish_baseline()
            _fim_ready = True
            print("[agent] FIM baseline established")
            return
        changes, _ = _fim.scan()
        for ch in changes:
            title = f"FIM {ch.get('type')}: {ch.get('path')}"
            cg_api_post("/v1/detections", {
                "source": "linux-agent-fim", "asset_id": ASSET,
                "severity": ch.get("severity") or "high", "confidence": 0.95, "title": title,
                "description": f"File integrity change: {ch}",
                "indicators": {"path": ch.get("path"), "hash": ch.get("hash"), "previous_hash": ch.get("previous_hash")},
                "tags": ["fim", "integrity", "ransomware"] if ch.get("type") == "modified" else ["fim", "integrity"],
                "tenant_id": TENANT,
            })
            print(f"[agent] FIM alert: {title}")
    except Exception as e:
        print(f"[agent] FIM error: {e}")


def net_scan():
    if _net is None:
        return
    try:
        for f in _net.find_suspicious(_net_seen):
            cg_api_post("/v1/detections", {
                "source": "linux-agent-net", "asset_id": ASSET,
                "severity": f.get("severity") or "high", "confidence": 0.75,
                "title": f.get("title") or "Suspicious outbound",
                "description": "Rare outbound destination port from host",
                "indicators": {"dst_ip": f.get("dst_ip"), "dst_port": f.get("dst_port"), "ip": f.get("dst_ip")},
                "tags": f.get("tags") or ["c2", "outbound"], "tenant_id": TENANT,
            })
            print(f"[agent] NET alert: {f.get('title')}")
    except Exception as e:
        print(f"[agent] netwatch error: {e}")


def scan_once():
    global scan_count, baseline_names
    poll_and_execute_commands()
    heartbeat()
    fim_scan()
    net_scan()
    procs = list_processes()
    names = {p["cmd"].split(" ")[0] for p in procs if p.get("cmd")}
    print(f"[agent] processes={len(procs)} scans={scan_count}")
    if scan_count < 3:
        baseline_names |= names
        if scan_count == 2:
            print(f"[agent] Baseline locked with {len(baseline_names)} process names")
    else:
        new = names - baseline_names
        if new and len(new) < 20:
            print(f"[agent] new process names vs baseline: {list(new)[:5]}")
    for p in procs:
        cmd_l = (p.get("cmd") or "").lower()
        for s in SUSPICIOUS:
            if s in cmd_l:
                title = f"Suspicious process: {s}"
                cg_api_post("/v1/detections", {
                    "source": "linux-agent", "asset_id": ASSET, "severity": "high", "confidence": 0.9,
                    "title": title, "description": f"Matched indicator '{s}' in process",
                    "indicators": {"pid": p["pid"], "cmdline": p["cmd"][:200], "cmdline_hint": p["cmd"][:200], "expected_starttime": p.get("start_time") or ""},
                    "tags": ["suspicious_process", "credential_access"] if "mimikatz" in s else ["suspicious_process"],
                    "tenant_id": TENANT,
                })
    scan_count += 1
    queue.flush(lambda path, payload: cg_api_post(path, payload)[0:2])
    print("[agent] scan complete")


def main():
    ap = argparse.ArgumentParser(description="CyberGuardian Linux agent")
    ap.add_argument("--interval", type=int, default=60)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    if not KEY:
        print("[agent] WARNING: CYBERGUARDIAN_API_KEY not set")
    print(f"[agent] API={API} asset={ASSET} version={VERSION}")
    register()
    if args.once:
        scan_once()
        return
    while True:
        try:
            scan_once()
        except Exception as e:
            print(f"[agent] loop error: {e}")
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    main()
