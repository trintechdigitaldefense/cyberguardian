#!/usr/bin/env python3
"""CyberGuardian Linux protective agent v1.1.0-pilot — stdlib HTTP, offline queue."""
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

API = os.environ.get("CYBERGUARDIAN_API") or os.environ.get("CG_CONTROLLER_URL") or "http://127.0.0.1:8080"
KEY = os.environ.get("CYBERGUARDIAN_API_KEY") or ""
ASSET = os.environ.get("CYBERGUARDIAN_ASSET_ID") or f"linux-{socket.gethostname()}"
TENANT = os.environ.get("CYBERGUARDIAN_TENANT") or "default"
VERSION = "1.1.0-pilot"

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


def register():
    ok, data = cg_api_post(
        "/v1/assets/register",
        {
            "asset_id": ASSET,
            "hostname": socket.gethostname(),
            "asset_type": "endpoint",
            "os": f"linux-{os.uname().release if hasattr(os, 'uname') else 'unknown'}",
            "tags": ["linux", "smart-agent", "fim", "baseline", f"v{VERSION}"],
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
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
                if not cmd:
                    cmd = Path(f"/proc/{pid}/comm").read_text(errors="ignore").strip()
                procs.append({"pid": pid, "cmd": cmd})
            except Exception:
                continue
    except Exception:
        pass
    return procs


def scan_once():
    global scan_count, baseline_names
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
                        "tags": ["suspicious_process", "credential_access"] if "mimikatz" in s else ["suspicious_process"],
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
                        "indicators": {"pid": p["pid"]},
                    },
                )
    scan_count += 1
    queue.flush(lambda path, payload: cg_api_post(path, payload)[0:2])
    print("[agent] scan complete")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=60)
    args = ap.parse_args()
    print(f"[agent] CyberGuardian Linux agent {VERSION} → {API} asset={ASSET}")
    if not KEY:
        print("[agent] WARNING: CYBERGUARDIAN_API_KEY not set")
    register()
    while True:
        try:
            scan_once()
        except Exception as e:
            print(f"[agent] scan error: {e}")
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    main()
