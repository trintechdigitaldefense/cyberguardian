from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
spec = importlib.util.spec_from_file_location("cg_dashboard_proxy_security", DASHBOARD_DIR / "main.py")
dashboard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dashboard
spec.loader.exec_module(dashboard)


def _request(peer: str, forwarded: str = "") -> Request:
    headers = []
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode("ascii")))
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "GET", "scheme": "http", "path": "/", "raw_path": b"/",
        "query_string": b"", "headers": headers,
        "client": (peer, 1234), "server": ("test", 80),
    }
    return Request(scope)


def test_forwarded_ip_is_used_only_for_configured_trusted_proxies(monkeypatch):
    monkeypatch.setenv("CG_TRUSTED_PROXY_IPS", "127.0.0.1/32,10.0.0.0/8")
    trusted = _request("127.0.0.1", "198.51.100.7, 10.0.0.4")
    assert dashboard._client_ip(trusted) == "198.51.100.7"

    untrusted = _request("192.0.2.5", "198.51.100.9")
    assert dashboard._client_ip(untrusted) == "192.0.2.5"

    malformed = _request("127.0.0.1", "attacker-controlled")
    assert dashboard._client_ip(malformed) == "127.0.0.1"


def test_invalid_trusted_proxy_network_is_not_silently_accepted(monkeypatch):
    monkeypatch.setenv("CG_TRUSTED_PROXY_IPS", "not-a-network")
    try:
        dashboard._trusted_proxy_networks()
    except ValueError:
        pass
    else:
        raise AssertionError("invalid trusted proxy network must be rejected")
