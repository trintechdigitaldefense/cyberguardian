"""Fleet lifecycle projection based on authenticated agent last-seen timestamps."""
from __future__ import annotations

import math
import time
from typing import Any


def _timestamp_age(last_seen: Any, current: float) -> int | None:
    try:
        seen_at = float(last_seen)
    except (TypeError, ValueError, OverflowError):
        return None
    # Reject NaN, infinity, zero/negative values and implausible future clocks.
    if not math.isfinite(seen_at) or seen_at <= 0 or seen_at > current + 60:
        return None
    return max(0, int(current - seen_at))


def project_fleet_lifecycle(items: list[dict[str, Any]], *, now: float | None = None,
                            stale_after_seconds: int = 180) -> list[dict[str, Any]]:
    current = time.time() if now is None else float(now)
    if not math.isfinite(current) or current <= 0:
        raise ValueError("fleet projection time must be a finite positive timestamp")
    threshold = max(30, int(stale_after_seconds))
    projected = []
    for original in items:
        item = dict(original)
        last_seen = item.get("last_seen")
        existing = str(item.get("status") or "").lower()
        age = _timestamp_age(last_seen, current)
        if existing in {"revoked", "disabled"}:
            item["lifecycle"] = existing
            item["last_seen_age_seconds"] = age
            item["stale"] = age is None or age > threshold
            projected.append(item)
            continue
        if age is None:
            item["lifecycle"] = "unknown"
            item["stale"] = True
            item["last_seen_age_seconds"] = None
            if existing == "online":
                item["status"] = "unknown"
        else:
            stale = age > threshold
            item["last_seen_age_seconds"] = age
            item["stale"] = stale
            item["lifecycle"] = "offline" if stale else "online"
            item["status"] = "offline" if stale else "online"
        projected.append(item)
    return projected
