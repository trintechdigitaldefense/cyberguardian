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
        for tool in ("iptables", "ip6tables"):
            if c._run([tool, "-N", "CG_TEST_KEEP"], timeout=5)[0] != 0:
                fail(f"could not create unrelated preservation chain with {tool}")
            if c._run([tool, "-A", "CG_TEST_KEEP", "-j", "ACCEPT"], timeout=5)[0] != 0:
                fail(f"could not add unrelated preservation rule with {tool}")
            if c._run([tool, "-I", "OUTPUT", "1", "-j", "CG_TEST_KEEP"], timeout=5)[0] != 0:
                fail(f"could not attach unrelated preservation chain with {tool}")
    else:
        # Prove the agent refuses a pre-existing same-named table it does not own.
        if c._run(["nft", "add", "table", c.NFT_FAMILY, c.NFT_TABLE], timeout=5)[0] != 0:
            fail("could not create unowned nftables collision fixture")
        if c._run(["nft", "add", "chain", c.NFT_FAMILY, c.NFT_TABLE, "foreign"], timeout=5)[0] != 0:
            fail("could not create unowned nftables chain fixture")
        if c._nft_ensure():
            fail("agent adopted an unowned same-named nftables table")
        if c._nft_owner_verified():
            fail("unowned nftables table passed ownership verification")
        if c._run(["nft", "delete", "table", c.NFT_FAMILY, c.NFT_TABLE], timeout=5)[0] != 0:
            fail("could not remove unowned nftables collision fixture")
        if c._run(["nft", "add", "table", c.NFT_FAMILY, "cg_test_unrelated"], timeout=5)[0] != 0:
            fail("could not create unrelated nftables preservation table")
        if c._run(["nft", "add", "chain", c.NFT_FAMILY, "cg_test_unrelated", "keep"], timeout=5)[0] != 0:
            fail("could not create unrelated nftables preservation chain")
        if c._run(["nft", "add", "rule", c.NFT_FAMILY, "cg_test_unrelated", "keep", "counter", "accept"], timeout=5)[0] != 0:
            fail("could not add unrelated nftables preservation rule")

    c._resolve_controller_ips = lambda _hint: [
        c.ipaddress.ip_address(CTRL_V4),
        c.ipaddress.ip_address(CTRL_V6),
    ]

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        identity = c._proc_identity(child.pid)
        if not identity or not identity.get("start_time"):
            fail("could not capture controlled child process identity")
        wrong_hint = c.kill_process(str(child.pid), expected_hint="not-this-process", expected_starttime=identity["start_time"])
        if wrong_hint.get("ok") or child.poll() is not None:
            fail("process command-line mismatch was not rejected safely")
        wrong_start = c.kill_process(str(child.pid), expected_hint=sys.executable, expected_starttime="0")
        if wrong_start.get("ok") or child.poll() is not None:
            fail("process start-time mismatch was not rejected safely")
        stopped = c.kill_process(str(child.pid), expected_hint=sys.executable, expected_starttime=identity["start_time"])
        if not stopped.get("ok"):
            fail(f"verified process termination failed: {stopped.get('detail')}")
        child.wait(timeout=4)
        print("PASS process command identity, start-time binding and safe termination")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)

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
        repeated = c.isolate_host(CTRL_V4)
        if not repeated.get("ok"):
            fail(f"idempotent isolate_host call failed: {repeated.get('detail')}")
        print("PASS idempotent isolation verification")

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
                if (
                    not c._iptables_rule_exists(tool, c.IPT_ISOLATE, ["-d", address, "-j", "ACCEPT"])
                    or not c._iptables_rule_exists(tool, c.IPT_ISOLATE, ["-j", "DROP"])
                ):
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
        if force_iptables:
            for tool in ("iptables", "ip6tables"):
                if not c._iptables_rule_exists(tool, "OUTPUT", ["-j", "CG_TEST_KEEP"]):
                    fail(f"{tool} unrelated OUTPUT jump was removed during restore")
                if not c._iptables_rule_exists(tool, "CG_TEST_KEEP", ["-j", "ACCEPT"]):
                    fail(f"{tool} unrelated preservation rule was removed during restore")
        else:
            if not c._nft_exists("table", c.NFT_FAMILY, "cg_test_unrelated"):
                fail("unrelated nftables table was removed during CyberGuardian restore")
            if "counter accept" not in c._run(["nft", "-a", "list", "chain", c.NFT_FAMILY, "cg_test_unrelated", "keep"], timeout=5)[1]:
                fail("unrelated nftables rule was removed during CyberGuardian restore")
        print("PASS unrelated firewall rules and chains preserved")

        # Inject a failure at the final isolation DROP rule. The implementation
        # must remove partially-applied isolation rules and keep a pending marker
        # so the normal restore path can finish cleanup.
        if isolated.get("backend") == "nft":
            original_add = c._nft_add_once
            def fail_nft_drop(chain, expression):
                if chain == c.NFT_ISOLATE and expression == ["drop"]:
                    return False
                return original_add(chain, expression)
            c._nft_add_once = fail_nft_drop
            try:
                partial = c.isolate_host(CTRL_V4)
            finally:
                c._nft_add_once = original_add
            if partial.get("ok"):
                fail("injected nft drop-rule failure was incorrectly reported as success")
            nft_rules = [line for line in c._nft_chain(c.NFT_ISOLATE).splitlines() if "# handle" in line and not line.lstrip().startswith(("table ", "chain "))]
            if nft_rules:
                fail("partial nft isolation rules remained after injected failure")
        else:
            original_add = c._iptables_add_once
            def fail_iptables_drop(tool, chain, args):
                if tool == "iptables" and chain == c.IPT_ISOLATE and args == ["-j", "DROP"]:
                    return False
                return original_add(tool, chain, args)
            c._iptables_add_once = fail_iptables_drop
            try:
                partial = c.isolate_host(CTRL_V4)
            finally:
                c._iptables_add_once = original_add
            if partial.get("ok"):
                fail("injected iptables drop-rule failure was incorrectly reported as success")
            for tool in ("iptables", "ip6tables"):
                if f"-A {c.IPT_ISOLATE} " in c._iptables_chain_rules(tool, c.IPT_ISOLATE):
                    fail(f"partial {tool} isolation rules remained after injected failure")

        pending = c._read_json(c.ISOLATE_MARKER, {})
        if pending.get("status") != "pending":
            fail("partial isolation failure did not retain pending recovery marker")
        recovered = c.restore_network()
        if not recovered.get("ok"):
            fail(f"recovery after partial rule failure failed: {recovered.get('detail')}")
        if c.ISOLATE_MARKER.exists() or c.BLOCK_MARKER.exists():
            fail("markers remain after partial-failure recovery")
        print("PASS partial firewall failure cleanup and pending-marker recovery")
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
