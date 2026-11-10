from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "agents" / "linux-ebpf"
sys.path.insert(0, str(AGENT_DIR))

spec = importlib.util.spec_from_file_location("cg_agent_heartbeat_test", AGENT_DIR / "agent.py")
agent = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = agent
spec.loader.exec_module(agent)


def test_registration_heartbeat_is_retried_fresh_not_queued(monkeypatch):
    captured = {}
    monkeypatch.setenv("CG_AGENT_IDENTITY_SECRET", "identity-secret-for-test")
    monkeypatch.setattr(agent.socket, "gethostname", lambda: "test-host")
    monkeypatch.setattr(agent, "_machine_id", lambda: "machine-test")

    def fake_post(path, payload, **kwargs):
        captured.update(path=path, payload=payload, kwargs=kwargs)
        return True, {"status": "online"}

    monkeypatch.setattr(agent, "cg_api_post", fake_post)
    assert agent.register() is True
    assert captured["path"] == "/v1/assets/register"
    assert captured["kwargs"]["queue_on_failure"] is False
    assert captured["payload"]["identity_sig"]


def test_failed_registration_does_not_enqueue_expiring_identity_envelope(monkeypatch):
    class QueueSpy:
        def __init__(self):
            self.calls = []

        def enqueue(self, *args):
            self.calls.append(args)
            return len(self.calls)

    queue = QueueSpy()
    monkeypatch.setattr(agent, "queue", queue)

    def unavailable(_request, timeout=10):
        raise OSError("controller offline")

    monkeypatch.setattr(agent.urllib.request, "urlopen", unavailable)
    ok, _ = agent.cg_api_post(
        "/v1/assets/register",
        {"asset_id": "test-host", "identity_ts": 1, "identity_sig": "expired"},
        queue_on_failure=False,
    )
    assert not ok
    assert queue.calls == []


def test_legacy_queued_registration_is_superseded_after_reconnect(monkeypatch):
    calls = []

    def fake_post(path, payload):
        calls.append((path, payload))
        return True, {"status": "accepted"}

    monkeypatch.setattr(agent, "cg_api_post", fake_post)
    ok, response = agent._deliver_queued_record(
        "/v1/assets/register",
        {"asset_id": "test-host", "identity_ts": 1, "identity_sig": "expired"},
    )
    assert ok
    assert response["status"] == "superseded_by_fresh_heartbeat"
    assert calls == []

    ok, response = agent._deliver_queued_record("/v1/detections", {"event_id": "evt-1"})
    assert ok and response["status"] == "accepted"
    assert calls == [("/v1/detections", {"event_id": "evt-1"})]



def test_permanent_auth_rejection_is_not_queued_and_marks_agent_revoked(monkeypatch):
    class QueueSpy:
        def __init__(self):
            self.calls = []

        def enqueue(self, *args):
            self.calls.append(args)
            return len(self.calls)

    queue = QueueSpy()
    monkeypatch.setattr(agent, "queue", queue)
    monkeypatch.setattr(agent, "AUTH_REJECTED", False)

    def forbidden(_request, timeout=10):
        raise agent.urllib.error.HTTPError(
            "http://controller/v1/detections", 403, "Forbidden", {}, None
        )

    monkeypatch.setattr(agent.urllib.request, "urlopen", forbidden)
    ok, response = agent.cg_api_post(
        "/v1/detections", {"asset_id": "revoked-host"}, queue_on_failure=True
    )
    assert not ok
    assert response["auth_error"] == 403
    assert agent.AUTH_REJECTED is True
    assert queue.calls == []


def test_get_auth_rejection_marks_agent_for_shutdown(monkeypatch):
    monkeypatch.setattr(agent, "AUTH_REJECTED", False)

    def unauthorized(_request, timeout=10):
        raise agent.urllib.error.HTTPError(
            "http://controller/v1/agent/commands", 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr(agent.urllib.request, "urlopen", unauthorized)
    ok, response = agent.cg_api_get("/v1/agent/commands?asset_id=host-a")
    assert not ok
    assert response["http_error"] == 401
    assert agent.AUTH_REJECTED is True



def test_transient_server_error_is_queued_for_retry(monkeypatch):
    class QueueSpy:
        def __init__(self):
            self.calls = []

        def enqueue(self, *args):
            self.calls.append(args)
            return len(self.calls)

    queue = QueueSpy()
    monkeypatch.setattr(agent, "queue", queue)
    monkeypatch.setattr(agent, "AUTH_REJECTED", False)

    def unavailable(_request, timeout=10):
        raise agent.urllib.error.HTTPError(
            "http://controller/v1/detections", 503, "Service Unavailable", {}, None
        )

    monkeypatch.setattr(agent.urllib.request, "urlopen", unavailable)
    ok, response = agent.cg_api_post(
        "/v1/detections", {"asset_id": "host-a"}, queue_on_failure=True
    )
    assert not ok
    assert response["http_error"] == 503
    assert agent.AUTH_REJECTED is False
    assert len(queue.calls) == 1
    assert queue.calls[0][1] == "/v1/detections"
