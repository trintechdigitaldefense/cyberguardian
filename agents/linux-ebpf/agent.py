#!/usr/bin/env python3
"""CyberGuardian Linux protective agent v1.2.0-tier1 — detect, queue, execute approved containment."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from offline_queue import OfflineQueue
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from offline_queue import OfflineQueue

try:
    from containment import execute_command
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from containment import execute_command

API = os.environ.get("CYBERGUARDIAN_API") or os.environ.get("CG_CONTROLLER_URL") or "http://127.0.0.1:8080"
KEY = os.environ.get("CYBERGUARDIAN_API_KEY") or ""
ASSET = os.environ.get("CYBERGUARDIAN_ASSET_ID") or f"linux-{socket.gethostname()}"
TENANT = os.environ.get("CYBERGUARDIAN_TENANT") or "default"
VERSION = "1.2.0-tier1"

queue = OfflineQueue()
baseline_names: set = set()
scan_count = 0

SUSPICIOUS = {
    "mimikatz",
    "powershell -enc",
    "nc.exe",
    "ncat",
    "meterpreter",
    "cobaltstrike",
}


def cg_api_post(path: str, payload: dict, timeout: int = 10):
    url = API.rstrip("/") + path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-API-Key": KEY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                return True, json.loads(body)
            except Exception:
                return True, {"raw": body}
    except Exception as e:
        queue.enqueue("POST", path, payload)
        print(f"[agent] POST {path} failed — queued: {e}")
        return False, {}


def cg_api_get(path: str, timeout: int = 10):
    url = API.rstrip("/") + path
    req = urllib.request.Request(url, headers={"X-API-Key": KEY}, method="GET")
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


def register():
    ok, data = cg_api_post(
        "/v1/assets/register",
        {
            "asset_id": ASSET,
            "hostname": socket.gethostname(),
            "asset_type": "endpoint",
            "os": f"linux-{os.uname().release if hasattr(os, 'uname') else 'unknown'}",
            "tags": ["linux", "smart-agent", "containment", f"v{VERSION}"],
            "agent_version": VERSION,
            "tenant_id": TENANT,
        },
    )
    print("[agent] registered →", data.get("status") if isinstance(data, dict) else data)
    return ok


def list_processes():
    procs = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                cmd = (
                    Path(f"/proc/{pid}/cmdline")
                    .read_bytes()
                    .replace(b"\x00", b" ")
                    .decode(errors="ignore")
                    .strip()
                )
                if not cmd:
                    cmd = Path(f"/proc/{pid}/comm").read_text(errors="ignore").strip()
                procs.append({"pid": pid, "cmd": cmd})
            except Exception:
                continue
    except Exception:
        pass
    return procs


def poll_and_execute_commands():
    """Pull approved commands for this asset and run real containment."""
    ok, data = cg_api_get(f"/v1/agent/commands?asset_id={ASSET}")
    if not ok or not isinstance(data, dict):
        return
    commands = data.get("commands") or []
    if not commands:
        return
    print(f"[agent] {len(commands)} command(s) to execute")
    for cmd in commands:
        cmd_id = cmd.get("id")
        action = cmd.get("action")
        print(f"[agent] executing {action} id={cmd_id} target={cmd.get('target')}")
        result = execute_command(cmd, controller_url=API)
        print(f"[agent] result ok={result.get('ok')} detail={result.get('detail')}")
        cg_api_post(
            "/v1/agent/command-result",
            {
                "command_id": cmd_id,
                "asset_id": ASSET,
                "action": action,
                "target": cmd.get("target"),
                "ok": bool(result.get("ok")),
                "detail": result.get("detail") or "",
                "result": result,
            },
        )


def scan_once():
    global scan_count, baseline_names
    poll_and_execute_commands()
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
                cg_api_post(
                    "/v1/detections",
                    {
                        "source": "linux-agent",
                        "asset_id": ASSET,
                        "severity": "high",
                        "confidence": 0.9,
                        "title": title,
                        "description": f"Matched indicator '{s}' in process",
                        "indicators": {"pid": p["pid"], "cmdline": p["cmd"][:200]},
                        "tags": ["suspicious_process", "credential_access"]
                        if "mimikatz" in s
                        else ["suspicious_process"],
                        "tenant_id": TENANT,
                    },
                )
                cg_api_post(
                    "/v1/issues/remember",
                    {
                        "title": title,
                        "asset_id": ASSET,
                        "severity": "high",
                        "source": "linux-agent",
                        "tags": ["suspicious_process"],
                        "indicators": {"pid": p["pid"], "cmdline": p["cmd"][:120]},
                    },
                )
    scan_count += 1
    queue.flush(lambda path, payload: cg_api_post(path, payload)[0:2])
    print("[agent] scan complete")


def main():
    ap = argparse.ArgumentParser(description="CyberGuardian Linux agent")
    ap.add_argument("--interval", type=int, default=60)
    ap.add_argument("--once", action="store_true", help="Single scan + command poll then exit")
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
