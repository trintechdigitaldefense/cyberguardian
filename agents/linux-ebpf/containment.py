#!/usr/bin/env python3
"""
CyberGuardian host containment — real kill / isolate / block on Linux.
Best-effort, reversible where possible. Authorized defensive use only.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STATE_DIR = Path.home() / ".cyberguardian"
STATE_DIR.mkdir(parents=True, exist_ok=True)
ISOLATE_MARKER = STATE_DIR / "isolate_active.json"
BLOCK_MARKER = STATE_DIR / "blocked_ips.json"


def _run(cmd: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def _has_nft() -> bool:
    return _run(["which", "nft"])[0] == 0


def _has_iptables() -> bool:
    return _run(["which", "iptables"])[0] == 0


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def kill_process(pid: str, expected_hint: str = "") -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "action": "kill_process",
        "target": str(pid),
        "ok": False,
        "detail": "",
        "ts": time.time(),
    }
    try:
        pid_i = int(str(pid).strip())
    except Exception:
        result["detail"] = "invalid pid"
        return result
    if pid_i <= 1:
        result["detail"] = "refusing to kill system pid"
        return result
    if pid_i == os.getpid():
        result["detail"] = "refusing to kill self"
        return result
    proc = Path(f"/proc/{pid_i}")
    if not proc.exists():
        result["ok"] = True
        result["detail"] = "process already gone"
        return result
    cmdline = ""
    try:
        cmdline = (proc / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
    except Exception:
        pass
    if expected_hint and expected_hint.lower() not in cmdline.lower() and expected_hint not in str(pid):
        result["detail"] = f"warning: hint '{expected_hint}' not in cmdline '{cmdline[:80]}'; proceeding"
    try:
        os.kill(pid_i, signal.SIGTERM)
        time.sleep(0.4)
        if proc.exists():
            os.kill(pid_i, signal.SIGKILL)
            time.sleep(0.2)
        gone = not proc.exists()
        result["ok"] = gone
        result["detail"] = (result.get("detail") + " | " if result.get("detail") else "") + (
            f"SIGTERM/SIGKILL sent; process {'gone' if gone else 'still present'}"
        )
        result["cmdline"] = cmdline[:200]
    except PermissionError:
        result["detail"] = "permission denied — agent needs sufficient privileges"
    except ProcessLookupError:
        result["ok"] = True
        result["detail"] = "process already gone"
    except Exception as e:
        result["detail"] = str(e)
    return result


def block_ip(ip: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "action": "block_ip",
        "target": ip,
        "ok": False,
        "detail": "",
        "ts": time.time(),
        "reversible": True,
    }
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1"):
        result["detail"] = "refusing to block loopback/invalid"
        return result
    if not _is_root():
        result["detail"] = "root required for network block (logged intent only)"
        result["intent_only"] = True
        return result
    if _has_nft():
        _run(["nft", "add", "table", "inet", "cyberguardian"], timeout=5)
        _run(
            ["nft", "add", "chain", "inet", "cyberguardian", "output", "{ type filter hook output priority 0; }"],
            timeout=5,
        )
        rc, out, err = _run(
            ["nft", "add", "rule", "inet", "cyberguardian", "output", "ip", "daddr", ip, "drop"],
            timeout=5,
        )
        if rc == 0:
            result["ok"] = True
            result["detail"] = f"nft drop {ip}"
            _record_block(ip, "nft")
            return result
        result["detail"] = f"nft failed: {err or out}"
    if _has_iptables():
        rc, out, err = _run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"], timeout=5)
        if rc == 0:
            result["ok"] = True
            result["detail"] = f"iptables DROP {ip}"
            _record_block(ip, "iptables")
            return result
        result["detail"] = (result.get("detail") or "") + f" | iptables: {err or out}"
    if not result["ok"] and not result.get("detail"):
        result["detail"] = "no nft/iptables available"
    return result


def isolate_host(controller_hint: str = "") -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "action": "isolate_host",
        "target": "self",
        "ok": False,
        "detail": "",
        "ts": time.time(),
        "reversible": True,
    }
    if ISOLATE_MARKER.exists():
        result["ok"] = True
        result["detail"] = "already isolated"
        return result
    if not _is_root():
        result["detail"] = "root required for isolation (intent logged only)"
        result["intent_only"] = True
        ISOLATE_MARKER.write_text(
            __import__("json").dumps({"ts": time.time(), "mode": "intent_only", "controller": controller_hint})
        )
        return result

    applied: List[str] = []
    if _has_nft():
        _run(["nft", "add", "table", "inet", "cyberguardian"], timeout=5)
        _run(
            ["nft", "add", "chain", "inet", "cyberguardian", "output", "{ type filter hook output priority 0; policy accept; }"],
            timeout=5,
        )
        _run(
            ["nft", "add", "rule", "inet", "cyberguardian", "output", "ct", "state", "established,related", "accept"],
            timeout=5,
        )
        _run(["nft", "add", "rule", "inet", "cyberguardian", "output", "udp", "dport", "53", "accept"], timeout=5)
        _run(["nft", "add", "rule", "inet", "cyberguardian", "output", "tcp", "dport", "53", "accept"], timeout=5)
        _run(["nft", "add", "rule", "inet", "cyberguardian", "output", "oif", "lo", "accept"], timeout=5)
        if controller_hint:
            host = controller_hint.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            if host and host.replace(".", "").isdigit():
                _run(
                    ["nft", "add", "rule", "inet", "cyberguardian", "output", "ip", "daddr", host, "accept"],
                    timeout=5,
                )
                applied.append(f"allow controller {host}")
        rc, out, err = _run(["nft", "add", "rule", "inet", "cyberguardian", "output", "drop"], timeout=5)
        if rc == 0:
            applied.append("nft output drop")
            result["ok"] = True
        else:
            result["detail"] = f"nft isolate partial: {err or out}"
    elif _has_iptables():
        steps = [
            ["iptables", "-I", "OUTPUT", "1", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "2", "-o", "lo", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "3", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "4", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-j", "DROP"],
        ]
        ok_any = False
        for s in steps:
            rc, _, err = _run(s, timeout=5)
            if rc == 0:
                ok_any = True
                applied.append(" ".join(s[1:4]))
            else:
                result["detail"] = (result.get("detail") or "") + f" | {err}"
        result["ok"] = ok_any
    else:
        result["detail"] = "no nft/iptables — isolation not applied"

    ISOLATE_MARKER.write_text(
        __import__("json").dumps(
            {
                "ts": time.time(),
                "mode": "nft" if _has_nft() else "iptables",
                "applied": applied,
                "controller": controller_hint,
            }
        )
    )
    if result["ok"]:
        result["detail"] = "isolated: " + ", ".join(applied)
    return result


def restore_network() -> Dict[str, Any]:
    result: Dict[str, Any] = {"action": "restore_network", "ok": False, "detail": "", "ts": time.time()}
    if not _is_root():
        result["detail"] = "root required"
        if ISOLATE_MARKER.exists():
            ISOLATE_MARKER.unlink(missing_ok=True)
        return result
    if _has_nft():
        rc, _, err = _run(["nft", "delete", "table", "inet", "cyberguardian"], timeout=8)
        if rc == 0:
            result["ok"] = True
            result["detail"] = "nft table cyberguardian removed"
        else:
            result["detail"] = f"nft delete: {err}"
    if ISOLATE_MARKER.exists():
        ISOLATE_MARKER.unlink(missing_ok=True)
        result["ok"] = True
        result["detail"] = (result.get("detail") or "") + " | marker cleared"
    return result


def _record_block(ip: str, backend: str):
    import json

    data = {"ips": {}}
    if BLOCK_MARKER.exists():
        try:
            data = json.loads(BLOCK_MARKER.read_text())
        except Exception:
            pass
    data.setdefault("ips", {})[ip] = {"backend": backend, "ts": time.time()}
    BLOCK_MARKER.write_text(json.dumps(data, indent=2))


def execute_command(cmd: Dict[str, Any], controller_url: str = "") -> Dict[str, Any]:
    action = (cmd.get("action") or "").strip()
    target = str(cmd.get("target") or "")
    params = cmd.get("parameters") or {}
    if action == "kill_process":
        hint = str(params.get("cmdline_hint") or params.get("hint") or "")
        return kill_process(target, expected_hint=hint)
    if action == "block_ip":
        return block_ip(target)
    if action == "isolate_host":
        return isolate_host(controller_hint=controller_url)
    if action == "restore_network":
        return restore_network()
    if action in ("alert_only", "escalate"):
        return {
            "action": action,
            "target": target,
            "ok": True,
            "detail": "no host change required",
            "ts": time.time(),
        }
    return {
        "action": action,
        "target": target,
        "ok": False,
        "detail": f"unknown action: {action}",
        "ts": time.time(),
    }
