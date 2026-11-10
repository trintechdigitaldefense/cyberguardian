from __future__ import annotations

import importlib.util
import json
import multiprocessing
import threading
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "agents" / "linux-ebpf" / "offline_queue.py"
spec = importlib.util.spec_from_file_location("cg_offline_queue_test", MODULE)
offline = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = offline
spec.loader.exec_module(offline)


def make_queue(tmp_path, **kwargs):
    return offline.OfflineQueue(
        tmp_path / "queue.jsonl",
        status_path=tmp_path / "status.json",
        **kwargs,
    )


def test_enqueue_is_durable_private_and_deduplicated(tmp_path):
    queue = make_queue(tmp_path)
    assert queue.enqueue("POST", "/v1/detections", {"asset_id": "a"}) == 1
    assert queue.enqueue("POST", "/v1/detections", {"asset_id": "a"}) == 1
    assert queue.size() == 1
    assert queue.path.stat().st_mode & 0o777 == 0o600
    record = json.loads(queue.path.read_text().splitlines()[0])
    assert record["id"]
    assert record["payload"]["asset_id"] == "a"


def test_overflow_rejects_new_event_and_preserves_existing(tmp_path):
    queue = make_queue(tmp_path, max_records=2, max_bytes=4096)
    queue.enqueue("POST", "/one", {"n": 1})
    queue.enqueue("POST", "/two", {"n": 2})
    try:
        queue.enqueue("POST", "/three", {"n": 3})
    except offline.QueueFullError:
        pass
    else:
        raise AssertionError("queue overflow must be explicit")
    records = [json.loads(line) for line in queue.path.read_text().splitlines()]
    assert [item["path"] for item in records] == ["/one", "/two"]
    assert queue.get_status()["overflow"] is True


def test_flush_removes_only_acknowledged_records(tmp_path):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/ack", {"n": 1})
    queue.enqueue("POST", "/retry", {"n": 2})
    result = queue.flush(lambda path, payload: (path == "/ack", {}), now=100)
    assert result == {"flushed": 1, "failed": 1, "remaining": 1, "deferred": 0}
    remaining = json.loads(queue.path.read_text().splitlines()[0])
    assert remaining["path"] == "/retry"
    assert remaining["attempts"] == 1
    assert remaining["next_attempt_at"] == 105
    # Retry is not attempted before its backoff expires.
    called = []
    result = queue.flush(lambda path, payload: called.append(path) or (True, {}), now=104)
    assert called == []
    assert result["deferred"] == 1
    result = queue.flush(lambda path, payload: (True, {}), now=105)
    assert result["flushed"] == 1
    assert queue.size() == 0


def test_flush_limit_bounds_work_and_keeps_unattempted_records(tmp_path):
    queue = make_queue(tmp_path)
    for n in range(5):
        queue.enqueue("POST", f"/{n}", {"n": n})
    result = queue.flush(lambda path, payload: (True, {}), now=100, limit=2)
    assert result["flushed"] == 2
    assert result["remaining"] == 3
    assert result["deferred"] == 3


def _enqueue_worker(path: str, status: str, start: int):
    queue = offline.OfflineQueue(Path(path), status_path=Path(status), max_records=100)
    for n in range(start, start + 10):
        queue.enqueue("POST", "/event", {"n": n})


def test_concurrent_writers_do_not_overwrite_each_other(tmp_path):
    path = tmp_path / "queue.jsonl"
    status = tmp_path / "status.json"
    workers = [
        multiprocessing.Process(target=_enqueue_worker, args=(str(path), str(status), i * 10))
        for i in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 40
    assert len({item["id"] for item in records}) == 40


def test_corrupt_records_are_retained_for_operator_inspection(tmp_path):
    queue = make_queue(tmp_path)
    queue.path.write_text("{not-json}\n")
    result = queue.flush(lambda path, payload: (True, {}), now=100)
    assert result["failed"] == 1
    assert queue.size() == 1
    assert "_corrupt_line" in json.loads(queue.path.read_text().splitlines()[0])



def test_enqueue_is_not_blocked_by_network_delivery(tmp_path):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/first", {"n": 1})
    entered = threading.Event()
    release = threading.Event()
    flush_result = {}

    def post_fn(path, payload):
        entered.set()
        assert release.wait(5)
        return True, {}

    flusher = threading.Thread(target=lambda: flush_result.update(queue.flush(post_fn, now=100)))
    flusher.start()
    assert entered.wait(5)

    enqueue_result = {}
    writer = threading.Thread(
        target=lambda: enqueue_result.update({"size": queue.enqueue("POST", "/second", {"n": 2})})
    )
    writer.start()
    writer.join(timeout=1)
    assert not writer.is_alive(), "enqueue must not wait for an HTTP delivery callback"
    release.set()
    flusher.join(timeout=5)
    writer.join(timeout=5)
    assert not flusher.is_alive()
    assert queue.size() == 1
    remaining = json.loads(queue.path.read_text().splitlines()[0])
    assert remaining["path"] == "/second"



def test_pending_records_survive_agent_process_restart_and_reconnect(tmp_path):
    first_process = make_queue(tmp_path)
    first_process.enqueue("POST", "/v1/detections", {"asset_id": "asset-a", "event_id": "event-1"})
    first_process.enqueue("POST", "/v1/heartbeat", {"asset_id": "asset-a", "sequence": 7})

    # Recreate the queue object as a restarted agent process would.
    restarted_process = make_queue(tmp_path)
    assert restarted_process.size() == 2
    delivered = []
    result = restarted_process.flush(
        lambda path, payload: delivered.append((path, payload)) or (True, {"status": "accepted"}),
        now=100,
    )
    assert result["flushed"] == 2
    assert restarted_process.size() == 0
    assert {path for path, _ in delivered} == {"/v1/detections", "/v1/heartbeat"}


def test_partial_delivery_keeps_unacknowledged_records_across_restart(tmp_path):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/v1/detections", {"event_id": "accepted"})
    queue.enqueue("POST", "/v1/detections", {"event_id": "not-accepted"})

    result = queue.flush(
        lambda path, payload: (payload["event_id"] == "accepted", {}),
        now=200,
    )
    assert result["flushed"] == 1
    assert result["failed"] == 1

    restarted = make_queue(tmp_path)
    assert restarted.size() == 1
    pending = json.loads(restarted.path.read_text().splitlines()[0])
    assert pending["payload"]["event_id"] == "not-accepted"
    assert pending["attempts"] == 1



def test_flush_exposes_stable_record_id_to_idempotent_callback(tmp_path):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/v1/detections", {"asset_id": "asset-a", "event_id": "event-42"})
    stored = json.loads(queue.path.read_text().splitlines()[0])
    delivered = []

    def post_fn(path, payload, *, record_id=None):
        delivered.append((path, payload, record_id))
        return True, {"status": "accepted"}

    result = queue.flush(post_fn, now=100)
    assert result["flushed"] == 1
    assert delivered == [("/v1/detections", stored["payload"], stored["id"])]



def test_queue_preserves_valid_json_records_with_invalid_schema(tmp_path):
    queue = make_queue(tmp_path)
    queue.path.write_text("null\n", encoding="utf-8")
    result = queue.flush(lambda path, payload: (True, {}), now=100)
    assert result["failed"] == 1
    preserved = json.loads(queue.path.read_text(encoding="utf-8").splitlines()[0])
    assert "_corrupt_line" in preserved
    assert preserved["_corrupt_line"] == "null"


def test_atomic_replace_failure_preserves_previous_queue(tmp_path, monkeypatch):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/first", {"event": "durable"})
    original = queue.path.read_bytes()

    def fail_replace(_source, _destination):
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(offline.os, "replace", fail_replace)
    try:
        queue.enqueue("POST", "/second", {"event": "must-not-partially-commit"})
    except OSError as exc:
        assert "simulated" in str(exc)
    else:
        raise AssertionError("simulated replace failure must propagate")
    assert queue.path.read_bytes() == original
    assert not list(tmp_path.glob("queue.jsonl.*.tmp"))


def test_fsync_failure_preserves_previous_queue(tmp_path, monkeypatch):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/first", {"event": "durable"})
    original = queue.path.read_bytes()

    def fail_fsync(_fd):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(offline.os, "fsync", fail_fsync)
    try:
        queue.enqueue("POST", "/second", {"event": "must-not-partially-commit"})
    except OSError as exc:
        assert "simulated" in str(exc)
    else:
        raise AssertionError("simulated fsync failure must propagate")
    assert queue.path.read_bytes() == original


def test_queue_directories_and_lock_files_are_private(tmp_path):
    queue = make_queue(tmp_path)
    assert queue.path.parent.stat().st_mode & 0o777 == 0o700
    assert queue.lock_path.stat().st_mode & 0o777 == 0o600
    assert queue.flush_lock_path.stat().st_mode & 0o777 == 0o600
    queue.set_status("online", 0)
    assert queue.status_path.stat().st_mode & 0o777 == 0o600



def test_queue_refuses_shared_directory_without_chmodding_it(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    try:
        offline.OfflineQueue(shared / "queue.jsonl")
    except PermissionError as exc:
        assert "must be private" in str(exc)
    else:
        raise AssertionError("shared queue directory must be rejected")
    assert shared.stat().st_mode & 0o777 == 0o755



def test_concurrent_flushers_are_serialized(tmp_path):
    queue = make_queue(tmp_path)
    queue.enqueue("POST", "/v1/detections", {"asset_id": "asset-a"})
    callback_started = threading.Event()
    release_callback = threading.Event()
    calls = []

    def post_fn(path, payload, record_id=None):
        calls.append(record_id)
        callback_started.set()
        release_callback.wait(timeout=2)
        return True, {"status": "accepted"}

    first = threading.Thread(target=queue.flush, args=(post_fn,), kwargs={"now": 100})
    second = threading.Thread(target=queue.flush, args=(post_fn,), kwargs={"now": 100})
    first.start()
    assert callback_started.wait(timeout=2)
    second.start()
    release_callback.set()
    first.join(timeout=3)
    second.join(timeout=3)
    assert not first.is_alive() and not second.is_alive()
    assert len(calls) == 1
    assert queue.pending_count() == 0



def test_queue_rejects_symlinked_storage_directory(tmp_path):
    real = tmp_path / "private"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    try:
        offline.OfflineQueue(linked / "queue.jsonl")
    except PermissionError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlinked queue directory must be rejected")



def test_queue_rejects_symlinked_lock_file(tmp_path):
    target = tmp_path / "target"
    target.write_text("do-not-touch", encoding="utf-8")
    queue_path = tmp_path / "queue.jsonl"
    (tmp_path / "queue.jsonl.lock").symlink_to(target)
    try:
        offline.OfflineQueue(queue_path)
    except PermissionError as exc:
        assert "lock" in str(exc)
    else:
        raise AssertionError("symlinked queue lock must be rejected")
    assert target.read_text(encoding="utf-8") == "do-not-touch"



def test_real_loopback_controller_outage_restart_and_reconnect(tmp_path):
    import socket
    import threading
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            received.append(payload["event_id"])
            body = json.dumps({"status": "accepted", "event_id": payload["event_id"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    queue = make_queue(tmp_path)
    for number in range(3):
        queue.enqueue("POST", "/v1/detections", {
            "asset_id": "agent-a", "tenant_id": "tenant-a", "event_id": f"offline-{number}",
        })

    def post_fn(path, payload, record_id=None):
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            endpoint + path, data=body,
            headers={"Content-Type": "application/json", "X-CG-Queue-Record-ID": record_id or ""},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=1) as response:
            return response.status == 200, json.loads(response.read().decode())

    outage = queue.flush(post_fn, now=100)
    assert outage == {"flushed": 0, "failed": 3, "remaining": 3, "deferred": 0}
    assert queue.size() == 3

    # Recreate the queue object as a restarted agent process would do.
    restarted = make_queue(tmp_path)
    assert restarted.size() == 3
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        reconnect = restarted.flush(post_fn, now=105)
        assert reconnect == {"flushed": 3, "failed": 0, "remaining": 0, "deferred": 0}
        assert restarted.size() == 0
        assert sorted(received) == ["offline-0", "offline-1", "offline-2"]
        assert restarted.get_status()["mode"] == "online"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_two_agent_queues_reconnect_without_crossing_tenant_payloads(tmp_path):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            received.append((payload["tenant_id"], payload["asset_id"], payload["event_id"]))
            body = b'{"status":"accepted"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        queues = {
            "agent-a": make_queue(tmp_path / "agent-a"),
            "agent-b": make_queue(tmp_path / "agent-b"),
        }
        for asset_id, tenant_id in (("agent-a", "tenant-a"), ("agent-b", "tenant-b")):
            for number in range(2):
                queues[asset_id].enqueue("POST", "/v1/detections", {
                    "asset_id": asset_id, "tenant_id": tenant_id,
                    "event_id": f"{asset_id}-{number}",
                })

        def deliver(path, payload, record_id=None):
            body = json.dumps(payload).encode()
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}" + path,
                data=body, headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status == 200, json.loads(response.read().decode())

        for queue in queues.values():
            result = queue.flush(deliver, now=200)
            assert result["flushed"] == 2
            assert result["remaining"] == 0
        assert len(received) == 4
        assert {tenant for tenant, _, _ in received} == {"tenant-a", "tenant-b"}
        assert {(tenant, asset) for tenant, asset, _ in received} == {
            ("tenant-a", "agent-a"), ("tenant-b", "agent-b")
        }
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
