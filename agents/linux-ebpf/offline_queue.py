"""Disk-backed offline queue for agent telemetry when controller is unreachable."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Dict

QUEUE = Path.home() / ".cyberguardian" / "offline_queue.jsonl"
STATUS = Path.home() / ".cyberguardian" / "connectivity.json"
MAX_LINES = 500


class OfflineQueue:
    def __init__(self, path: Path = QUEUE):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def enqueue(self, kind: str, path: str, payload: Dict[str, Any]) -> int:
        rec = {"ts": time.time(), "kind": kind, "path": path, "payload": payload}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        self.set_status("degraded", queued=self.size())
        return self.size()

    def size(self) -> int:
        if not self.path.exists():
            return 0
        return sum(1 for _ in open(self.path) if _.strip())

    def flush(self, post_fn: Callable) -> Dict[str, Any]:
        if not self.path.exists():
            self.set_status("online", queued=0)
            return {"flushed": 0, "failed": 0}
        lines = [l for l in self.path.read_text().splitlines() if l.strip()]
        kept, flushed, failed = [], 0, 0
        for line in lines[-MAX_LINES:]:
            try:
                rec = json.loads(line)
                ok, _ = post_fn(rec["path"], rec["payload"])
                if ok:
                    flushed += 1
                else:
                    kept.append(line)
                    failed += 1
            except Exception:
                kept.append(line)
                failed += 1
        self.path.write_text("\n".join(kept) + ("\n" if kept else ""))
        self.set_status("online" if failed == 0 else "degraded", queued=len(kept))
        return {"flushed": flushed, "failed": failed, "remaining": len(kept)}

    def set_status(self, mode: str, queued: int = 0):
        STATUS.parent.mkdir(parents=True, exist_ok=True)
        STATUS.write_text(json.dumps({"mode": mode, "queued": queued, "ts": time.time()}))

    def get_status(self) -> Dict[str, Any]:
        if not STATUS.exists():
            return {"mode": "unknown", "queued": 0}
        try:
            return json.loads(STATUS.read_text())
        except Exception:
            return {"mode": "unknown", "queued": 0}
