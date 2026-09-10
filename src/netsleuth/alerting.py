from __future__ import annotations

import httpx

from netsleuth.config import Watch

_BAD_STATUSES = {"warn", "crit"}
_GOOD_STATUSES = {"ok", "info"}


def should_fire(
    previous: str | None,
    current: str,
    last_fired_at: float | None,
    now: float,
    watch: Watch,
) -> bool:
    if previous is None or previous == current:
        return False
    if current in _BAD_STATUSES:
        event = current
    elif previous in _BAD_STATUSES and current in _GOOD_STATUSES:
        event = "recovered"
    else:
        return False
    if event not in set(watch.webhook_on):
        return False
    if (
        last_fired_at is not None
        and (now - last_fired_at) < watch.webhook_min_interval_seconds
    ):
        return False
    return True


def build_payload(
    session_meta: dict, cycle_summary: dict, previous: str | None, current: str
) -> dict:
    return {
        "tool": "netsleuth",
        "asn": session_meta.get("asn"),
        "at": cycle_summary.get("at"),
        "previous": previous,
        "current": current,
        "score": cycle_summary.get("score"),
        "findings": cycle_summary.get("finding_ids") or [],
        "host": session_meta.get("interface"),
    }


async def post_webhook(
    client: httpx.AsyncClient, url: str, payload: dict, timeout: float
) -> bool:
    try:
        response = await client.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        return True
    except httpx.HTTPError, OSError:
        return False
