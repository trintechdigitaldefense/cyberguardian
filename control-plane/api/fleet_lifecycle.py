"""Fleet lifecycle projection based on authenticated agent last-seen timestamps."""
from __future__ import annotations

import time
from typing import Any


def project_fleet_lifecycle(items: list[dict[str, Any]], *, now: float | None = None,
                            stale_after_seconds: int = 180) -> list[dict[str, Any]]:
    current = time.time() if now is None else float(now)
    threshold = max(30, int(stale_after_seconds))
    projected = []
    for original in items:
        item = dict(original)
        last_seen = item.get("last_seen")
        try:
            seen_at = float(last_seen)
        except (TypeError, ValueError):
            item["lifecycle"] = "unknown"
            item["stale"] = True
            item["last_seen_age_seconds"] = None
            if item.get("status") == "online":
                item["status"] = "unknown"
        else:
            age = max(0, int(current - seen_at))
            stale = age > threshold
            item["last_seen_age_seconds"] = age
            item["stale"] = stale
            item["lifecycle"] = "offline" if stale else "online"
            if stale:
                item["status"] = "offline"
            elif item.get("status") not in {"revoked", "disabled"}:
                item["status"] = "online"
        projected.append(item)
    return projected
