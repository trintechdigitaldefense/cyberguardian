#!/usr/bin/env python3
"""Run real firewall containment checks inside a disposable network namespace.

Run from a disposable Linux VM with:
    sudo python3 scripts/test_containment_namespace.py

This script refuses to run firewall mutations in the caller's network namespace.
It requires root, util-linux 'unshare', and either nftables or both iptables tools.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "agents" / "linux-ebpf"
TEST_V4 = "198.51.100.77"
TEST_V6 = "2001:db8::77"
CTRL_V4 = "192.0.2.20"
CTRL_V6 = "2001:db8::20"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def enter_namespace() -> int:
    if os.geteuid() != 0:
        fail("run with sudo/root inside a disposable Linux VM")
    if not shutil.which("unshare"):
        fail("util-linux unshare is required")
    state_dir = tempfile.mkdtemp(prefix="cyberguardian-containment-test-")
    env = os.environ.copy()
    env["CG_STATE_DIR"] = state_dir
    env["CG_PARENT_NETNS"] = os.readlink("/proc/self/ns/net")
    try:
        proc = subprocess.run(
            ["unshare", "--net", "--fork", sys.executable, str(Path(__file__).resolve()), "--inside"],
            env=env,
            check=False,
        )
        return proc.returncode
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def inside_namespace() -> int:
    if os.geteuid() != 0:
        fail("namespace process is not root")
    current_ns = os.readlink("/proc/self/ns/net")
    if current_ns == os.environ.get("CG_PARENT_NETNS"):
        fail("network namespace did not change; refusing to touch host firewall")

    sys.path.insert(0, str(AGENT_DIR))
    import containment as c  # imported only after isolated state path is set

    nft_available = bool(shutil.which("nft"))
    iptables_available = bool(shutil.which("iptables") and shutil.which("ip6tables"))
    force_iptables = os.environ.get("CG_FORCE_IPTABLES") == "1"
    if not nft_available and not iptables_available:
        fail("need nft, or both iptables and ip6tables")
    if force_iptables and not iptables_available:
        fail("CG_FORCE_IPTABLES=1 requires both iptables and ip6tables")
    if force_iptables:
        c._has_nft = lambda: False

    c._resolve_controller_ips = lambda _hint: [
        c.ipaddress.ip_address(CTRL_V4),
        c.ipaddress.ip_address(CTRL_V6),
    ]

    try:
        for address in (TEST_V4, TEST_V6):
            result = c.block_ip(address)
            if not result.get("ok"):
                fail(f"block_ip({address}) failed: {result.get('detail')}")
            print(f"PASS block_ip {address} via {result.get('backend')}")

        isolated = c.isolate_host(CTRL_V4)
        if not isolated.get("ok"):
            fail(f"isolate_host failed: {isolated.get('detail')}")
        print(f"PASS isolate_host via {isolated.get('backend')}")

        marker = c._read_json(c.ISOLATE_MARKER, {})
        if marker.get("status") != "active":
            fail("isolation marker is not active after verified isolation")

        if isolated.get("backend") == "nft":
            for address in (CTRL_V4, CTRL_V6):
                family = "ip" if ":" not in address else "ip6"
                if not c._nft_rule_present(c.NFT_ISOLATE, [family, "daddr", address, "accept"]):
                    fail(f"nft controller recovery allow rule missing for {address}")
            if not c._nft_rule_present(c.NFT_ISOLATE, ["drop"]):
                fail("nft isolation drop rule missing")
            print("PASS nftables controller allowlist and final drop")
        else:
            for tool, address in (("iptables", CTRL_V4), ("ip6tables", CTRL_V6)):
                rules = c._iptables_chain_rules(tool, c.IPT_ISOLATE)
                if f"-d {address} -j ACCEPT" not in rules or "-j DROP" not in rules:
                    fail(f"{tool} controller allowlist/final drop missing")
            print("PASS dual-stack iptables controller allowlist and final drop")

        restored = c.restore_network()
        if not restored.get("ok"):
            fail(f"restore_network failed: {restored.get('detail')}")
        if c.ISOLATE_MARKER.exists() or c.BLOCK_MARKER.exists():
            fail("recovery markers remain after successful restore")
        if nft_available and c._nft_exists("table", c.NFT_FAMILY, c.NFT_TABLE):
            fail("CyberGuardian nftables table remains after restore")
        for tool, chain in (
            ("iptables", c.IPT_OUTPUT), ("iptables", c.IPT_ISOLATE), ("iptables", c.IPT_BLOCK),
            ("ip6tables", c.IPT_OUTPUT), ("ip6tables", c.IPT_ISOLATE), ("ip6tables", c.IPT_BLOCK),
        ):
            if shutil.which(tool) and subprocess.run([tool, "-S", chain], capture_output=True).returncode == 0:
                fail(f"{tool} chain {chain} remains after restore")
        print("PASS verified rollback and marker cleanup")
        print("RESULT: all namespace containment checks passed")
        return 0
    finally:
        # Best-effort cleanup if any assertion above fails; namespace exit is the final safety boundary.
        try:
            c.restore_network()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(inside_namespace() if "--inside" in sys.argv else enter_namespace())
