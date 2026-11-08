#!/usr/bin/env python3
"""Scoped, reversible Linux containment for CyberGuardian.

All firewall changes are confined to CyberGuardian-owned chains/table. The
module refuses ambiguous process targets and never flushes host firewall rules.
Destructive paths must be tested in disposable VMs or with mocked commands.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

STATE_DIR = Path(os.environ.get("CG_STATE_DIR") or (Path.home() / ".cyberguardian"))
STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
try:
    STATE_DIR.chmod(0o700)
except OSError:
    pass
ISOLATE_MARKER = STATE_DIR / "isolate_active.json"
BLOCK_MARKER = STATE_DIR / "blocked_ips.json"

NFT_FAMILY = "inet"
NFT_TABLE = "cyberguardian"
NFT_OWNER = "cg_owner"
NFT_OWNER_COMMENT = "CyberGuardian managed table v1"
NFT_OUTPUT = "cg_output"
NFT_ISOLATE = "cg_isolate"
NFT_BLOCK = "cg_block"
IPT_OUTPUT = "CG_OUTPUT"
IPT_ISOLATE = "CG_ISOLATE"
IPT_BLOCK = "CG_BLOCK"


def _run(cmd: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)


def _has_nft() -> bool:
    return shutil.which("nft") is not None


def _has_iptables() -> bool:
    return shutil.which("iptables") is not None


def _has_ip6tables() -> bool:
    return shutil.which("ip6tables") is not None


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def _write_json_atomic(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        path.chmod(0o600)
    finally:
        try:
            if os.path.exists(name):
                os.unlink(name)
        except OSError:
            pass


def _read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {"_invalid_marker": True}
    except FileNotFoundError:
        # A first-run state file is expected to be absent; use the clean default.
        return dict(default)
    except (OSError, ValueError):
        # Existing but unreadable/corrupt state must never be mistaken for empty state.
        return {"_invalid_marker": True}


def _proc_identity(pid: int) -> Optional[Dict[str, str]]:
    """Read Linux proc identity. starttime is field 22 and survives PID reuse."""
    proc = Path(f"/proc/{pid}")
    if not proc.exists():
        return None
    stat_text = (proc / "stat").read_text(encoding="utf-8")
    close = stat_text.rfind(")")
    if close < 0:
        raise ValueError("invalid /proc stat record")
    fields = stat_text[close + 2 :].split()
    if len(fields) <= 19:
        raise ValueError("incomplete /proc stat record")
    start_time = fields[19]
    state = fields[0]
    try:
        cmdline = (proc / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
    except OSError:
        cmdline = ""
    if not cmdline:
        try:
            cmdline = (proc / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            cmdline = ""
    return {"start_time": start_time, "state": state, "cmdline": cmdline}

def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _signal_bound_process(pid: int, pidfd: Optional[int], start_time: str, sig: int) -> bool:
    """Signal the opened process handle where supported; otherwise recheck starttime."""
    pidfd_sender = getattr(signal, "pidfd_send_signal", None)
    if pidfd is not None and pidfd_sender is not None:
        pidfd_sender(pidfd, sig, None, 0)
        return True
    current = _proc_identity(pid)
    if not current or current["start_time"] != start_time or current["state"] == "Z":
        return False
    os.kill(pid, sig)
    return True


def kill_process(
    pid: str,
    expected_hint: str = "",
    expected_starttime: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "action": "kill_process", "target": str(pid), "ok": False, "detail": "", "ts": time.time()
    }
    try:
        pid_num = int(str(pid).strip())
    except (TypeError, ValueError):
        result["detail"] = "invalid pid"
        return result
    if pid_num <= 1 or pid_num == os.getpid():
        result["detail"] = "refusing system pid or self"
        return result

    try:
        identity = _proc_identity(pid_num)
    except (OSError, ValueError) as exc:
        result["detail"] = f"unable to verify process identity: {exc}"
        return result
    if identity is None or identity["state"] == "Z":
        result["ok"] = True
        result["detail"] = "process already gone"
        return result
    if not expected_hint and not expected_starttime:
        result["detail"] = "process identity evidence required (cmdline_hint or starttime)"
        return result
    if expected_starttime and str(expected_starttime) != identity["start_time"]:
        result["detail"] = "process starttime mismatch; possible PID reuse"
        return result
    if expected_hint and expected_hint.casefold() not in identity["cmdline"].casefold():
        result["detail"] = "process command-line hint mismatch; refusing action"
        return result

    bound_start = identity["start_time"]
    pidfd: Optional[int] = None
    opener = getattr(os, "pidfd_open", None)
    if opener is not None:
        try:
            pidfd = opener(pid_num, 0)
        except OSError:
            pidfd = None

    try:
        current = _proc_identity(pid_num)
        if not current or current["start_time"] != bound_start:
            result["detail"] = "process identity changed before signal; refusing action"
            return result
        _signal_bound_process(pid_num, pidfd, bound_start, signal.SIGTERM)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if pidfd is not None and _pidfd_exited(pidfd):
                break
            current = _proc_identity(pid_num)
            if not current or current["start_time"] != bound_start or current["state"] == "Z":
                break
            time.sleep(0.05)
        current = _proc_identity(pid_num)
        still_same = bool(current and current["start_time"] == bound_start and current["state"] != "Z")
        if still_same:
            _signal_bound_process(pid_num, pidfd, bound_start, signal.SIGKILL)
            time.sleep(0.1)
        current = _proc_identity(pid_num)
        gone = not current or current["start_time"] != bound_start or current["state"] == "Z"
        result["ok"] = gone
        result["detail"] = "SIGTERM/SIGKILL completed" if gone else "process remains; no further signal sent"
        result["cmdline"] = identity["cmdline"][:200]
        result["start_time"] = bound_start
    except PermissionError:
        result["detail"] = "permission denied — agent needs sufficient privileges"
    except ProcessLookupError:
        result["ok"] = True
        result["detail"] = "process already gone"
    except Exception as exc:
        result["detail"] = str(exc)
    finally:
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError:
                pass
    return result


def _parse_ip(value: str) -> Tuple[Optional[ipaddress._BaseAddress], str]:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, "invalid IP address"
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        return None, "refusing loopback, unspecified, multicast or link-local address"
    return address, ""


def _nft_exists(kind: str, *names: str) -> bool:
    return _run(["nft", "list", kind, *names], timeout=5)[0] == 0


def _nft_chain(chain: str) -> str:
    return _run(["nft", "-a", "list", "chain", NFT_FAMILY, NFT_TABLE, chain], timeout=5)[1]


def _normalize_nft_rules(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value)
    normalized = re.sub(r"\s*,\s*", ",", normalized)
    normalized = re.sub(r\'"([^"]*)"\', r"\\1", normalized)
    return normalized.replace("{ ", "{").replace(" }", "}").strip()


def _nft_rule_present(chain: str, expression: List[str]) -> bool:
    rendered = _normalize_nft_rules(" ".join(expression))
    listing = _normalize_nft_rules(_nft_chain(chain))
    # Token boundaries matter: 192.0.2.1 must never match 192.0.2.10.
    pattern = rf"(?<![\w.:]){re.escape(rendered)}(?![\w.:])"
    return re.search(pattern, listing) is not None


def _nft_add_once(chain: str, expression: List[str]) -> bool:
    if _nft_rule_present(chain, expression):
        return True
    rc, out, err = _run(["nft", "add", "rule", NFT_FAMILY, NFT_TABLE, chain, *expression], timeout=5)
    if rc != 0:
        return False
    # Never treat table existence or a prefix/substring as proof that the rule is active.
    return _nft_rule_present(chain, expression)

def _nft_owner_verified() -> bool:
    if not _nft_exists("chain", NFT_FAMILY, NFT_TABLE, NFT_OWNER):
        return False
    listing = _nft_chain(NFT_OWNER)
    return f'comment "{NFT_OWNER_COMMENT}"' in listing


def _nft_ensure() -> bool:
    if not _nft_exists("table", NFT_FAMILY, NFT_TABLE):
        if _run(["nft", "add", "table", NFT_FAMILY, NFT_TABLE], timeout=5)[0] != 0:
            return False
        owner_definition = f'{{ comment "{NFT_OWNER_COMMENT}"; }}'
        if _run(["nft", "add", "chain", NFT_FAMILY, NFT_TABLE, NFT_OWNER, owner_definition], timeout=5)[0] != 0:
            return False
    elif not _nft_owner_verified():
        # Never adopt or later delete a same-named table that another component owns.
        return False
    if not _nft_owner_verified():
        return False
    if not _nft_exists("chain", NFT_FAMILY, NFT_TABLE, NFT_OUTPUT):
        base = "{ type filter hook output priority 0; policy accept; }"
        if _run(["nft", "add", "chain", NFT_FAMILY, NFT_TABLE, NFT_OUTPUT, base], timeout=5)[0] != 0:
            return False
    base_listing = _nft_chain(NFT_OUTPUT)
    if "hook output" not in base_listing or "policy accept" not in base_listing:
        return False
    for chain in (NFT_ISOLATE, NFT_BLOCK):
        if not _nft_exists("chain", NFT_FAMILY, NFT_TABLE, chain):
            if _run(["nft", "add", "chain", NFT_FAMILY, NFT_TABLE, chain], timeout=5)[0] != 0:
                return False
    if not _nft_add_once(NFT_OUTPUT, ["jump", NFT_ISOLATE]):
        return False
    if not _nft_add_once(NFT_OUTPUT, ["jump", NFT_BLOCK]):
        return False
    return True


def _resolve_controller_ips(controller_hint: str) -> List[ipaddress._BaseAddress]:
    if not controller_hint:
        return []
    raw = controller_hint.strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError:
        return []
    found = set()
    for info in infos:
        try:
            found.add(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return sorted(found, key=lambda item: (item.version, int(item)))


def _nft_add_controller_allow(address: ipaddress._BaseAddress) -> bool:
    family = "ip" if address.version == 4 else "ip6"
    return _nft_add_once(NFT_ISOLATE, [family, "daddr", str(address), "accept"])


def _iptables_tool(version: int) -> Optional[str]:
    tool = "iptables" if version == 4 else "ip6tables"
    return tool if shutil.which(tool) else None


def _iptables_chain_rules(tool: str, chain: str) -> str:
    return _run([tool, "-S", chain], timeout=5)[1]


def _iptables_ensure(tool: str) -> bool:
    for chain in (IPT_OUTPUT, IPT_ISOLATE, IPT_BLOCK):
        if _run([tool, "-S", chain], timeout=5)[0] != 0:
            if _run([tool, "-N", chain], timeout=5)[0] != 0:
                return False
    output_rules = _iptables_chain_rules(tool, "OUTPUT")
    if f"-A OUTPUT -j {IPT_OUTPUT}" not in output_rules:
        if _run([tool, "-I", "OUTPUT", "1", "-j", IPT_OUTPUT], timeout=5)[0] != 0:
            return False
    rules = _iptables_chain_rules(tool, IPT_OUTPUT)
    for target in (IPT_ISOLATE, IPT_BLOCK):
        line = f"-A {IPT_OUTPUT} -j {target}"
        if line not in rules and _run([tool, "-A", IPT_OUTPUT, "-j", target], timeout=5)[0] != 0:
            return False
    return True


def _iptables_add_once(tool: str, chain: str, args: List[str]) -> bool:
    rules = _iptables_chain_rules(tool, chain)
    line = f"-A {chain} " + " ".join(args)
    if line in rules:
        return True
    if _run([tool, "-A", chain, *args], timeout=5)[0] != 0:
        return False
    return line in _iptables_chain_rules(tool, chain)


def _record_block(address: ipaddress._BaseAddress, backend: str, status: str = "active") -> None:
    data = _read_json(BLOCK_MARKER, {"ips": {}})
    if data.get("_invalid_marker") or not isinstance(data.get("ips"), dict):
        raise ValueError("block state marker is corrupt; refusing untracked firewall changes")
    data.setdefault("ips", {})[str(address)] = {
        "version": address.version, "backend": backend, "status": status, "ts": time.time()
    }
    _write_json_atomic(BLOCK_MARKER, data)


def block_ip(ip: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "action": "block_ip", "target": str(ip), "ok": False, "detail": "", "ts": time.time(), "reversible": True
    }
    address, error = _parse_ip(ip)
    if address is None:
        result["detail"] = error
        return result
    if not _is_root():
        result["detail"] = "root required for network block; no firewall changes made"
        result["intent_only"] = True
        return result

    if _has_nft():
        backend = "nft"
        family = "ip" if address.version == 4 else "ip6"
        try:
            # Persist recovery intent before making any firewall change.
            _record_block(address, backend, status="pending")
        except (OSError, ValueError) as exc:
            result["detail"] = f"cannot persist rollback marker; no firewall rule applied: {exc}"
            return result
        if _nft_ensure() and _nft_add_once(NFT_BLOCK, [family, "daddr", str(address), "drop"]):
            if _nft_rule_present(NFT_BLOCK, [family, "daddr", str(address), "drop"]):
                try:
                    _record_block(address, backend, status="active")
                except OSError as exc:
                    result["detail"] = f"block applied but active marker update failed; pending recovery marker retained: {exc}"
                    return result
                result.update(ok=True, detail=f"nft {family} drop {address}", backend=backend)
                return result
        result["detail"] = "nft rule could not be applied and verified; pending recovery marker retained"
        return result

    tool = _iptables_tool(address.version)
    if tool:
        try:
            _record_block(address, tool, status="pending")
        except (OSError, ValueError) as exc:
            result["detail"] = f"cannot persist rollback marker; no firewall rule applied: {exc}"
            return result
        if _iptables_ensure(tool) and _iptables_add_once(tool, IPT_BLOCK, ["-d", str(address), "-j", "DROP"]):
            try:
                _record_block(address, tool, status="active")
            except OSError as exc:
                result["detail"] = f"block applied but active marker update failed; pending recovery marker retained: {exc}"
                return result
            result.update(ok=True, detail=f"{tool} DROP {address}", backend=tool)
            return result
    result["detail"] = "no supported firewall backend could apply and verify the block; recovery marker retained if written"
    return result


def _clear_iptables_isolation() -> None:
    for tool in ("iptables", "ip6tables"):
        if shutil.which(tool) is not None and _run([tool, "-S", IPT_ISOLATE], timeout=5)[0] == 0:
            _run([tool, "-F", IPT_ISOLATE], timeout=5)


def isolate_host(controller_hint: str = "") -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "action": "isolate_host", "target": "self", "ok": False, "detail": "", "ts": time.time(), "reversible": True
    }
    controller_ips = _resolve_controller_ips(controller_hint)
    if not controller_ips:
        result["detail"] = "controller recovery address could not be resolved; isolation refused"
        return result
    if not _is_root():
        result["detail"] = "root required for isolation; no firewall changes made"
        result["intent_only"] = True
        return result

    if ISOLATE_MARKER.exists():
        marker = _read_json(ISOLATE_MARKER, {})
        backend = marker.get("backend")
        if marker.get("status") == "active" and backend == "nft" and _has_nft() and _nft_exists("table", NFT_FAMILY, NFT_TABLE):
            listing = _nft_chain(NFT_ISOLATE)
            if "drop" in listing and all(str(addr) in listing for addr in controller_ips):
                result.update(ok=True, detail="already isolated; firewall state verified", backend=backend)
                return result
        if marker.get("status") == "active" and backend == "iptables+ip6tables":
            verified = True
            for version, address in ((ip.version, ip) for ip in controller_ips):
                tool = _iptables_tool(version)
                rules = _iptables_chain_rules(tool, IPT_ISOLATE) if tool else ""
                if not tool or "-j DROP" not in rules or f"-d {address} -j ACCEPT" not in rules:
                    verified = False
                    break
            if verified:
                result.update(ok=True, detail="already isolated; dual-stack firewall state verified", backend=backend)
                return result
        # A stale marker is not proof of isolation. Reapply from observed state.
        ISOLATE_MARKER.unlink(missing_ok=True)

    applied: List[str] = []
    if _has_nft():
        if not _nft_ensure():
            result["detail"] = "nft table/chain setup failed; isolation not applied"
            return result
        backend = "nft"
        try:
            _write_json_atomic(ISOLATE_MARKER, {
                "status": "pending", "ts": time.time(), "backend": backend,
                "controller": controller_hint, "controller_ips": [str(ip) for ip in controller_ips],
                "applied": [],
            })
        except OSError as exc:
            result["detail"] = f"cannot persist isolation recovery marker; no isolation rules applied: {exc}"
            return result
        rules = [
            ["oifname", "lo", "accept"],
            ["icmp", "type", "{", "destination-unreachable", ",", "time-exceeded", ",", "parameter-problem", "}", "accept"],
            ["icmpv6", "type", "nd-neighbor-solicit", "accept"],
            ["icmpv6", "type", "nd-neighbor-advert", "accept"],
            ["icmpv6", "type", "destination-unreachable", "accept"],
            ["icmpv6", "type", "packet-too-big", "accept"],
            ["icmpv6", "type", "time-exceeded", "accept"],
            ["icmpv6", "type", "parameter-problem", "accept"],
        ]
        for rule in rules:
            if not _nft_add_once(NFT_ISOLATE, rule):
                _run(["nft", "flush", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE], timeout=5)
                result["detail"] = f"failed to add nft isolation allow rule: {' '.join(rule)}"
                return result
        for address in controller_ips:
            if not _nft_add_controller_allow(address):
                _run(["nft", "flush", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE], timeout=5)
                result["detail"] = f"failed to add controller recovery allow rule for {address}"
                return result
            applied.append(f"allow controller {address}")
        if not _nft_add_once(NFT_ISOLATE, ["drop"]):
            _run(["nft", "flush", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE], timeout=5)
            result["detail"] = "failed to add nft isolation drop rule"
            return result
        listing = _nft_chain(NFT_ISOLATE)
        if "drop" not in listing or not all(str(addr) in listing for addr in controller_ips):
            _run(["nft", "flush", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE], timeout=5)
            result["detail"] = "nft isolation verification failed"
            return result
        applied.append("nft scoped output isolation")
        backend = "nft"
    else:
        tools = {4: _iptables_tool(4), 6: _iptables_tool(6)}
        if not tools[4] or not tools[6]:
            result["detail"] = "dual-stack nftables or both iptables/ip6tables are required for safe isolation"
            return result
        for tool in (tools[4], tools[6]):
            if not _iptables_ensure(tool):
                _clear_iptables_isolation()
                result["detail"] = f"failed to create CyberGuardian-owned chains with {tool}"
                return result
        backend = "iptables+ip6tables"
        try:
            _write_json_atomic(ISOLATE_MARKER, {
                "status": "pending", "ts": time.time(), "backend": backend,
                "controller": controller_hint, "controller_ips": [str(ip) for ip in controller_ips],
                "applied": [],
            })
        except OSError as exc:
            result["detail"] = f"cannot persist isolation recovery marker; no isolation rules applied: {exc}"
            return result
        allow_rules = {
            tools[4]: [
                ["-o", "lo", "-j", "ACCEPT"],
                ["-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "ACCEPT"],
                ["-p", "icmp", "--icmp-type", "time-exceeded", "-j", "ACCEPT"],
                ["-p", "icmp", "--icmp-type", "parameter-problem", "-j", "ACCEPT"],
            ],
            tools[6]: [
                ["-o", "lo", "-j", "ACCEPT"],
                ["-p", "ipv6-icmp", "--icmpv6-type", "neighbour-solicitation", "-j", "ACCEPT"],
                ["-p", "ipv6-icmp", "--icmpv6-type", "neighbour-advertisement", "-j", "ACCEPT"],
                ["-p", "ipv6-icmp", "--icmpv6-type", "destination-unreachable", "-j", "ACCEPT"],
                ["-p", "ipv6-icmp", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"],
                ["-p", "ipv6-icmp", "--icmpv6-type", "time-exceeded", "-j", "ACCEPT"],
                ["-p", "ipv6-icmp", "--icmpv6-type", "parameter-problem", "-j", "ACCEPT"],
            ],
        }
        for tool in (tools[4], tools[6]):
            for rule in allow_rules[tool]:
                if not _iptables_add_once(tool, IPT_ISOLATE, rule):
                    _clear_iptables_isolation()
                    result["detail"] = f"failed to add isolation allow rule with {tool}"
                    return result
        for address in controller_ips:
            tool = tools[address.version]
            if not _iptables_add_once(tool, IPT_ISOLATE, ["-d", str(address), "-j", "ACCEPT"]):
                _clear_iptables_isolation()
                result["detail"] = f"failed to add controller recovery allow rule for {address}"
                return result
            applied.append(f"allow controller {address}")
        for tool in (tools[4], tools[6]):
            if not _iptables_add_once(tool, IPT_ISOLATE, ["-j", "DROP"]):
                _clear_iptables_isolation()
                result["detail"] = f"failed to add isolation drop rule with {tool}"
                return result
            if "-j DROP" not in _iptables_chain_rules(tool, IPT_ISOLATE):
                _clear_iptables_isolation()
                result["detail"] = f"isolation drop verification failed with {tool}"
                return result
        applied.append("scoped dual-stack iptables isolation")
        backend = "iptables+ip6tables"

    try:
        _write_json_atomic(ISOLATE_MARKER, {
            "status": "active", "ts": time.time(), "backend": backend,
            "controller": controller_hint, "controller_ips": [str(ip) for ip in controller_ips],
            "applied": applied,
        })
    except OSError as exc:
        result["detail"] = f"isolation rules applied but active marker update failed; pending recovery marker retained: {exc}"
        return result
    result.update(ok=True, detail="isolated with verified CyberGuardian-owned rules: " + ", ".join(applied), backend=backend)
    return result


def _cleanup_iptables(tool: str) -> bool:
    if shutil.which(tool) is None:
        return True
    output_rules = _iptables_chain_rules(tool, "OUTPUT")
    jump = f"-A OUTPUT -j {IPT_OUTPUT}"
    while jump in output_rules:
        if _run([tool, "-D", "OUTPUT", "-j", IPT_OUTPUT], timeout=5)[0] != 0:
            return False
        output_rules = _iptables_chain_rules(tool, "OUTPUT")
    for chain in (IPT_OUTPUT, IPT_ISOLATE, IPT_BLOCK):
        if _run([tool, "-S", chain], timeout=5)[0] == 0:
            if _run([tool, "-F", chain], timeout=5)[0] != 0:
                return False
            if _run([tool, "-X", chain], timeout=5)[0] != 0:
                return False
    if f"-A OUTPUT -j {IPT_OUTPUT}" in _iptables_chain_rules(tool, "OUTPUT"):
        return False
    return all(_run([tool, "-S", chain], timeout=5)[0] != 0 for chain in (IPT_OUTPUT, IPT_ISOLATE, IPT_BLOCK))


def restore_network() -> Dict[str, Any]:
    result: Dict[str, Any] = {"action": "restore_network", "ok": False, "detail": "", "ts": time.time()}
    if not _is_root():
        result["detail"] = "root required; markers retained and no firewall state changed"
        return result

    failures = []
    isolation_record = _read_json(ISOLATE_MARKER, {})
    block_record = _read_json(BLOCK_MARKER, {"ips": {}})
    if isolation_record.get("_invalid_marker") or block_record.get("_invalid_marker"):
        failures.append("containment state marker is corrupt; refusing to claim verified restoration")
    blocked_ips = block_record.get("ips") if isinstance(block_record.get("ips"), dict) else {}
    recorded_backends = {str(isolation_record.get("backend") or "")}
    recorded_backends.update(
        str(item.get("backend") or "")
        for item in blocked_ips.values()
        if isinstance(item, dict)
    )
    if "nft" in recorded_backends and not _has_nft():
        failures.append("nftables backend unavailable; cannot verify or restore recorded nft rules")
    if "iptables" in recorded_backends and not _has_iptables():
        failures.append("iptables backend unavailable; cannot verify or restore recorded IPv4 rules")
    if "ip6tables" in recorded_backends and not _has_ip6tables():
        failures.append("ip6tables backend unavailable; cannot verify or restore recorded IPv6 rules")
    if "iptables+ip6tables" in recorded_backends and (not _has_iptables() or not _has_ip6tables()):
        failures.append("dual-stack iptables backend incomplete; cannot verify full restore")
    if _has_nft() and _nft_exists("table", NFT_FAMILY, NFT_TABLE):
        if not _nft_owner_verified():
            failures.append("refusing to delete same-named nft table without CyberGuardian ownership marker")
        else:
            rc, out, err = _run(["nft", "delete", "table", NFT_FAMILY, NFT_TABLE], timeout=8)
            if rc != 0 or _nft_exists("table", NFT_FAMILY, NFT_TABLE):
                failures.append(f"nft cleanup failed: {err or out or 'table still exists'}")

    for tool in ("iptables", "ip6tables"):
        if shutil.which(tool) is not None and not _cleanup_iptables(tool):
            failures.append(f"{tool} CyberGuardian chain cleanup failed")

    nft_left = _has_nft() and _nft_exists("table", NFT_FAMILY, NFT_TABLE)
    iptables_left = any(
        shutil.which(tool) is not None and _run([tool, "-S", chain], timeout=5)[0] == 0
        for tool in ("iptables", "ip6tables")
        for chain in (IPT_OUTPUT, IPT_ISOLATE, IPT_BLOCK)
    )
    if nft_left or iptables_left:
        failures.append("CyberGuardian firewall artifacts remain after cleanup")
    if failures:
        result["detail"] = "; ".join(failures)
        return result

    for marker in (ISOLATE_MARKER, BLOCK_MARKER):
        try:
            marker.unlink(missing_ok=True)
        except OSError as exc:
            failures.append(f"could not remove {marker.name}: {exc}")
    if failures:
        result["detail"] = "; ".join(failures)
        return result
    result.update(ok=True, detail="verified: CyberGuardian-owned nftables/iptables rules removed")
    return result


def execute_command(cmd: Dict[str, Any], controller_url: str = "") -> Dict[str, Any]:
    action = str(cmd.get("action") or "").strip()
    target = str(cmd.get("target") or "")
    params = cmd.get("parameters") if isinstance(cmd.get("parameters"), dict) else {}
    if action == "kill_process":
        hint = str(params.get("cmdline_hint") or params.get("hint") or "")
        start_time = params.get("expected_starttime") or params.get("start_time")
        return kill_process(target, expected_hint=hint, expected_starttime=str(start_time) if start_time else None)
    if action == "block_ip":
        return block_ip(target)
    if action == "isolate_host":
        return isolate_host(controller_hint=controller_url)
    if action == "restore_network":
        return restore_network()
    if action in ("alert_only", "escalate"):
        return {"action": action, "target": target, "ok": True, "detail": "no host change required", "ts": time.time()}
    return {"action": action, "target": target, "ok": False, "detail": f"unknown action: {action}", "ts": time.time()}
