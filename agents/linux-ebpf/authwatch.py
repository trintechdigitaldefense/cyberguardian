"""
Login / sudo anomaly signals from auth logs (best-effort).
Reads journalctl when available, else /var/log/auth.log or secure.
Authorized defensive use only.
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Set

STATE = Path.home() / ".cyberguardian" / "authwatch_offset.txt"
STATE.parent.mkdir(parents=True, exist_ok=True)

FAIL_SSH = re.compile(r"Failed password for(?: invalid user)? (\S+) from (\S+)", re.I)
INVALID_USER = re.compile(r"Invalid user (\S+) from (\S+)", re.I)
SUDO_FAIL = re.compile(r"sudo:.*?authentication failure|FAILED su for|sudo:.*COMMAND=", re.I)
ROOT_LOGIN = re.compile(r"Accepted \S+ for root from (\S+)", re.I)


def _read_new_lines(max_lines: int = 400) -> List[str]:
    lines: List[str] = []
    try:
        p = subprocess.run(
            ["journalctl", "-u", "ssh", "-u", "sshd", "-t", "sudo", "-n", str(max_lines), "--no-pager", "-o", "cat"],
            capture_output=True, text=True, timeout=8,
        )
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.splitlines()[-max_lines:]
    except Exception:
        pass
    for path in ("/var/log/auth.log", "/var/log/secure"):
        try:
            return Path(path).read_text(errors="ignore").splitlines()[-max_lines:]
        except Exception:
            continue
    return lines


def scan(seen: Set[str] | None = None) -> List[Dict[str, Any]]:
    seen = seen if seen is not None else set()
    findings: List[Dict[str, Any]] = []
    lines = _read_new_lines()
    fail_by_ip: Dict[str, int] = {}

    for line in lines:
        m = FAIL_SSH.search(line) or INVALID_USER.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            fail_by_ip[ip] = fail_by_ip.get(ip, 0) + 1
            continue
        if ROOT_LOGIN.search(line):
            m2 = ROOT_LOGIN.search(line)
            ip = m2.group(1) if m2 else "unknown"
            key = f"root_login:{ip}:{int(time.time()) // 300}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"Root SSH login from {ip}",
                    "severity": "high", "confidence": 0.85,
                    "tags": ["auth", "root_login", "credential_access"],
                    "indicators": {"src_ip": ip, "user": "root"},
                    "description": line.strip()[:240],
                })
            continue
        if SUDO_FAIL.search(line) and "authentication failure" in line.lower():
            key = f"sudo_fail:{hash(line) % 10**8}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": "Sudo authentication failure",
                    "severity": "medium", "confidence": 0.8,
                    "tags": ["auth", "sudo", "credential_access"],
                    "indicators": {},
                    "description": line.strip()[:240],
                })

    for ip, count in fail_by_ip.items():
        if count >= 5:
            key = f"bruteforce:{ip}:{int(time.time()) // 600}"
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "title": f"SSH brute-force pattern from {ip} ({count} fails)",
                "severity": "high", "confidence": 0.9,
                "tags": ["auth", "bruteforce", "credential_access"],
                "indicators": {"src_ip": ip, "fail_count": count, "ip": ip},
                "description": f"Multiple failed SSH attempts from {ip}",
            })
    return findings
