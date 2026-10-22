"""Outbound connection watch — rare ports / suspicious destinations (best-effort)."""
from __future__ import annotations

import socket
import time
from typing import Any, Dict, List, Set

RARE_PORTS = {4444, 5555, 6666, 6667, 1337, 31337, 8081, 8443, 9001, 4443, 1080, 3128}
PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "::1", "fe80:")


def _parse_ipv4_hex(h: str) -> str:
    try:
        b = bytes.fromhex(h)
        return socket.inet_ntoa(b[::-1])
    except Exception:
        return "0.0.0.0"


def _parse_port_hex(h: str) -> int:
    try:
        return int(h, 16)
    except Exception:
        return 0


def _is_172_private(ip: str) -> bool:
    try:
        second = int(ip.split(".")[1])
        return 16 <= second <= 31
    except Exception:
        return False


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES) or (ip.startswith("172.") and _is_172_private(ip))


def read_tcp_conns() -> List[Dict[str, Any]]:
    conns: List[Dict[str, Any]] = []
    try:
        lines = open("/proc/net/tcp").read().splitlines()[1:]
    except Exception:
        return conns
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        rem, state = parts[2], parts[3]
        if state != "01":
            continue
        try:
            rip_hex, rport_hex = rem.split(":")
            rip = _parse_ipv4_hex(rip_hex)
            rport = _parse_port_hex(rport_hex)
        except Exception:
            continue
        if rip in ("0.0.0.0", "127.0.0.1"):
            continue
        conns.append({"dst_ip": rip, "dst_port": rport, "state": "ESTABLISHED", "ts": time.time()})
    return conns


def find_suspicious(seen: Set[str] | None = None) -> List[Dict[str, Any]]:
    seen = seen if seen is not None else set()
    findings: List[Dict[str, Any]] = []
    for c in read_tcp_conns():
        key = f"{c['dst_ip']}:{c['dst_port']}"
        if key in seen:
            continue
        port = int(c["dst_port"])
        if port not in RARE_PORTS:
            continue
        if _is_private(c["dst_ip"]):
            continue
        seen.add(key)
        findings.append({
            "dst_ip": c["dst_ip"],
            "dst_port": port,
            "title": f"Rare outbound port {port} to {c['dst_ip']}",
            "severity": "high",
            "tags": ["c2", "beacon", "outbound"],
        })
    return findings
