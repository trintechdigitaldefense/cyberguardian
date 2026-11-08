from __future__ import annotations

import ipaddress
import json
import os
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agents" / "linux-ebpf"
sys.path.insert(0, str(AGENT))
import containment as c


def _state_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "STATE_DIR", tmp_path)
    monkeypatch.setattr(c, "ISOLATE_MARKER", tmp_path / "isolate_active.json")
    monkeypatch.setattr(c, "BLOCK_MARKER", tmp_path / "blocked_ips.json")


def test_kill_process_requires_process_identity(monkeypatch):
    monkeypatch.setattr(c, "_proc_identity", lambda pid: {
        "start_time": "123", "state": "S", "cmdline": "python worker.py"
    })
    signals = []
    monkeypatch.setattr(c.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    result = c.kill_process("2345")
    assert not result["ok"]
    assert "identity evidence required" in result["detail"]
    assert signals == []


def test_kill_process_rejects_hint_mismatch(monkeypatch):
    monkeypatch.setattr(c, "_proc_identity", lambda pid: {
        "start_time": "123", "state": "S", "cmdline": "python safe_worker.py"
    })
    signals = []
    monkeypatch.setattr(c.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    result = c.kill_process("2345", expected_hint="malware")
    assert not result["ok"]
    assert "hint mismatch" in result["detail"]
    assert signals == []


def test_kill_process_rejects_pid_reuse_starttime(monkeypatch):
    monkeypatch.setattr(c, "_proc_identity", lambda pid: {
        "start_time": "999", "state": "S", "cmdline": "python worker.py"
    })
    result = c.kill_process("2345", expected_starttime="123")
    assert not result["ok"]
    assert "PID reuse" in result["detail"]



def test_kill_process_refuses_unreadable_proc_identity(monkeypatch):
    def unreadable(pid):
        raise PermissionError("procfs denied")
    monkeypatch.setattr(c, "_proc_identity", unreadable)
    result = c.kill_process("2345", expected_starttime="123")
    assert not result["ok"]
    assert "unable to verify process identity" in result["detail"]

def test_kill_process_uses_pidfd_bound_to_same_starttime(monkeypatch):
    calls = []
    snapshots = [
        {"start_time": "123", "state": "S", "cmdline": "python worker.py"},
        {"start_time": "123", "state": "S", "cmdline": "python worker.py"},
        None,
    ]
    monkeypatch.setattr(c, "_proc_identity", lambda pid: snapshots.pop(0) if snapshots else None)
    monkeypatch.setattr(c.os, "pidfd_open", lambda pid, flags: 77, raising=False)
    monkeypatch.setattr(c.signal, "pidfd_send_signal", lambda fd, sig, info, flags: calls.append((fd, sig)), raising=False)
    monkeypatch.setattr(c, "_pidfd_exited", lambda fd: True)
    monkeypatch.setattr(c.os, "close", lambda fd: None)
    monkeypatch.setattr(c.time, "sleep", lambda value: None)
    result = c.kill_process("2345", expected_hint="worker.py")
    assert result["ok"], result
    assert calls == [(77, signal.SIGTERM)]


def test_block_ip_rejects_invalid_and_loopback():
    assert not c.block_ip("not-an-ip")["ok"]
    assert not c.block_ip("127.0.0.1")["ok"]
    assert not c.block_ip("ff02::1")["ok"]


def test_block_ip_uses_nft_inet_for_ipv6(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(c, "_is_root", lambda: True)
    monkeypatch.setattr(c, "_has_nft", lambda: True)
    monkeypatch.setattr(c, "_nft_ensure", lambda: True)
    commands = []
    monkeypatch.setattr(c, "_nft_add_once", lambda chain, expr: commands.append((chain, expr)) or True)
    monkeypatch.setattr(c, "_nft_chain", lambda chain: "ip6 daddr 2001:4860::1 drop")
    monkeypatch.setattr(c, "_record_block", lambda address, backend: None)
    result = c.block_ip("2001:4860::1")
    assert result["ok"], result
    assert (c.NFT_BLOCK, ["ip6", "daddr", "2001:4860::1", "drop"]) in commands


def test_isolation_requires_controller_recovery_address(monkeypatch):
    monkeypatch.setattr(c, "_resolve_controller_ips", lambda hint: [])
    monkeypatch.setattr(c, "_is_root", lambda: True)
    result = c.isolate_host("https://controller.example:8080")
    assert not result["ok"]
    assert "recovery address" in result["detail"]


def test_nft_isolation_has_controller_allow_and_final_drop(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    controller = ipaddress.ip_address("192.0.2.10")
    monkeypatch.setattr(c, "_resolve_controller_ips", lambda hint: [controller])
    monkeypatch.setattr(c, "_is_root", lambda: True)
    monkeypatch.setattr(c, "_has_nft", lambda: True)
    monkeypatch.setattr(c, "_nft_ensure", lambda: True)
    commands = []
    monkeypatch.setattr(c, "_nft_add_once", lambda chain, expr: commands.append((chain, expr)) or True)
    monkeypatch.setattr(c, "_nft_chain", lambda chain: "ip daddr 192.0.2.10 accept\ndrop")
    monkeypatch.setattr(c, "_write_json_atomic", lambda path, value: path.write_text(json.dumps(value)))
    result = c.isolate_host("https://controller.example:8080")
    assert result["ok"], result
    assert (c.NFT_ISOLATE, ["ip", "daddr", "192.0.2.10", "accept"]) in commands
    assert (c.NFT_ISOLATE, ["drop"]) in commands
    marker = json.loads(c.ISOLATE_MARKER.read_text())
    assert marker["status"] == "active"



def test_nft_rule_is_not_success_until_rule_is_visible(monkeypatch):
    monkeypatch.setattr(c, "_nft_chain", lambda chain: "")
    monkeypatch.setattr(c, "_run", lambda args, timeout=8: (0, "", ""))
    assert not c._nft_add_once(c.NFT_BLOCK, ["ip", "daddr", "192.0.2.1", "drop"])


def test_nft_existing_rule_is_detected_with_normalized_format(monkeypatch):
    monkeypatch.setattr(c, "_nft_chain", lambda chain: "ip daddr 192.0.2.1 drop")
    monkeypatch.setattr(c, "_run", lambda args, timeout=8: (_ for _ in ()).throw(AssertionError("duplicate rule add")))
    assert c._nft_add_once(c.NFT_BLOCK, ["ip", "daddr", "192.0.2.1", "drop"])


def test_nft_ensure_rejects_foreign_or_wrong_hook_base_chain(monkeypatch):
    monkeypatch.setattr(c, "_nft_exists", lambda kind, *names: True)
    monkeypatch.setattr(c, "_nft_chain", lambda chain: "type filter hook input priority 0; policy accept;")
    assert not c._nft_ensure()

def test_restore_without_root_retains_markers(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    c.ISOLATE_MARKER.write_text("{}")
    monkeypatch.setattr(c, "_is_root", lambda: False)
    result = c.restore_network()
    assert not result["ok"]
    assert c.ISOLATE_MARKER.exists()


def test_restore_deletes_only_cyberguardian_nft_table(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    c.ISOLATE_MARKER.write_text("{}")
    c.BLOCK_MARKER.write_text("{}")
    monkeypatch.setattr(c, "_is_root", lambda: True)
    monkeypatch.setattr(c, "_has_nft", lambda: True)
    monkeypatch.setattr(c.shutil, "which", lambda tool: None if tool in ("iptables", "ip6tables") else "/usr/sbin/nft")
    state = {"exists": True}
    def exists(kind, *names):
        return state["exists"]
    monkeypatch.setattr(c, "_nft_exists", exists)
    commands = []
    def run(args, timeout=8):
        commands.append(args)
        if args[:3] == ["nft", "delete", "table"]:
            state["exists"] = False
            return 0, "", ""
        return 0, "", ""
    monkeypatch.setattr(c, "_run", run)
    monkeypatch.setattr(c, "_cleanup_iptables", lambda tool: True)
    result = c.restore_network()
    assert result["ok"], result
    assert ["nft", "delete", "table", "inet", "cyberguardian"] in commands
    assert not c.ISOLATE_MARKER.exists()
    assert not c.BLOCK_MARKER.exists()


def test_execute_command_passes_starttime_to_process_guard(monkeypatch):
    captured = {}
    def fake_kill(pid, expected_hint="", expected_starttime=None):
        captured.update(pid=pid, hint=expected_hint, starttime=expected_starttime)
        return {"ok": True}
    monkeypatch.setattr(c, "kill_process", fake_kill)
    result = c.execute_command({
        "action": "kill_process",
        "target": "321",
        "parameters": {"cmdline_hint": "worker.py", "expected_starttime": "456"},
    })
    assert result["ok"]
    assert captured == {"pid": "321", "hint": "worker.py", "starttime": "456"}


def test_nft_isolation_does_not_allow_general_dns_or_established_egress(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    controller = ipaddress.ip_address("192.0.2.10")
    monkeypatch.setattr(c, "_resolve_controller_ips", lambda hint: [controller])
    monkeypatch.setattr(c, "_is_root", lambda: True)
    monkeypatch.setattr(c, "_has_nft", lambda: True)
    monkeypatch.setattr(c, "_nft_ensure", lambda: True)
    commands = []
    monkeypatch.setattr(c, "_nft_add_once", lambda chain, expr: commands.append((chain, expr)) or True)
    monkeypatch.setattr(c, "_nft_chain", lambda chain: "ip daddr 192.0.2.10 accept\\ndrop")
    monkeypatch.setattr(c, "_write_json_atomic", lambda path, value: None)
    result = c.isolate_host("https://controller.example:8080")
    assert result["ok"], result
    rendered = [" ".join(expr) for _, expr in commands]
    assert not any("dport 53" in rule for rule in rendered)
    assert not any("ct state established" in rule for rule in rendered)


def test_iptables_fallback_requires_and_configures_both_families(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    v4 = ipaddress.ip_address("192.0.2.10")
    v6 = ipaddress.ip_address("2001:4860::1")
    monkeypatch.setattr(c, "_resolve_controller_ips", lambda hint: [v4, v6])
    monkeypatch.setattr(c, "_is_root", lambda: True)
    monkeypatch.setattr(c, "_has_nft", lambda: False)
    monkeypatch.setattr(c.shutil, "which", lambda tool: f"/sbin/{tool}" if tool in ("iptables", "ip6tables") else None)
    monkeypatch.setattr(c, "_iptables_ensure", lambda tool: True)
    monkeypatch.setattr(c, "_write_json_atomic", lambda path, value: None)
    calls = []
    monkeypatch.setattr(c, "_iptables_add_once", lambda tool, chain, args: calls.append((tool, chain, args)) or True)
    monkeypatch.setattr(c, "_iptables_chain_rules", lambda tool, chain: "-j DROP")
    result = c.isolate_host("https://controller.example:8080")
    assert result["ok"], result
    assert ("iptables", c.IPT_ISOLATE, ["-d", "192.0.2.10", "-j", "ACCEPT"]) in calls
    assert ("ip6tables", c.IPT_ISOLATE, ["-d", "2001:4860::1", "-j", "ACCEPT"]) in calls
    assert ("iptables", c.IPT_ISOLATE, ["-j", "DROP"]) in calls
    assert ("ip6tables", c.IPT_ISOLATE, ["-j", "DROP"]) in calls


def test_restore_retains_marker_if_recorded_backend_is_missing(monkeypatch, tmp_path):
    _state_paths(tmp_path, monkeypatch)
    c.ISOLATE_MARKER.write_text(json.dumps({"status": "active", "backend": "nft"}))
    monkeypatch.setattr(c, "_is_root", lambda: True)
    monkeypatch.setattr(c, "_has_nft", lambda: False)
    monkeypatch.setattr(c, "_has_iptables", lambda: False)
    monkeypatch.setattr(c, "_has_ip6tables", lambda: False)
    monkeypatch.setattr(c.shutil, "which", lambda tool: None)
    result = c.restore_network()
    assert not result["ok"]
    assert "backend unavailable" in result["detail"]
    assert c.ISOLATE_MARKER.exists()
