from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import httpx

from netcheck.config import Providers
from netcheck.models import BgpEvent

# These calls return the whole routing history of an ASN; on a large ISP that is
# tens of megabytes unless the window and row count are pinned.
BULK_CALLS = {"bgp-updates", "routing-history", "bgplay", "announced-prefixes"}

_UNSTABLE_WITHDRAWALS_PER_DAY = 3.0


def _as_label(asn: object) -> str:
    text = str(asn).upper()
    return text if text.startswith("AS") else f"AS{text}"


def parse_as_overview(payload: dict) -> dict[str, str | None]:
    data = payload.get("data") or {}
    block = data.get("block") or {}
    return {
        "holder": data.get("holder") or None,
        "registry": block.get("name") or None,
        "allocated_at": data.get("announced_since") or None,
    }


def parse_asn_neighbours(payload: dict) -> tuple[list[str], list[str], list[str]]:
    upstreams: list[str] = []
    peers: list[str] = []
    downstreams: list[str] = []
    for neighbour in (payload.get("data") or {}).get("neighbours") or []:
        label = _as_label(neighbour.get("asn"))
        kind = neighbour.get("type")
        if kind == "left":
            upstreams.append(label)
        elif kind == "right":
            downstreams.append(label)
        else:
            peers.append(label)
    return upstreams, peers, downstreams


def parse_announced_prefixes(payload: dict) -> tuple[list[str], int, int]:
    prefixes: list[str] = []
    v4 = v6 = 0
    for entry in (payload.get("data") or {}).get("prefixes") or []:
        prefix = entry.get("prefix")
        if not prefix:
            continue
        prefixes.append(prefix)
        try:
            version = ipaddress.ip_network(prefix, strict=False).version
        except ValueError:
            continue
        if version == 4:
            v4 += 1
        else:
            v6 += 1
    return prefixes, v4, v6


def parse_bgp_updates(payload: dict) -> list[BgpEvent]:
    events: list[BgpEvent] = []
    for update in (payload.get("data") or {}).get("updates") or []:
        attrs = update.get("attrs") or {}
        events.append(
            BgpEvent(
                timestamp=update.get("timestamp", ""),
                type=update.get("type", ""),
                prefix=attrs.get("target_prefix"),
                path=[int(hop) for hop in attrs.get("path") or []],
            )
        )
    return events


def classify_stability(events: list[BgpEvent], days: int) -> str:
    if days <= 0:
        return "unknown"
    withdrawals = sum(1 for e in events if e.type == "W")
    return "unstable" if withdrawals / days >= _UNSTABLE_WITHDRAWALS_PER_DAY else "stable"


async def ripestat(
    client: httpx.AsyncClient,
    providers: Providers,
    call: str,
    resource: str,
    **extra: str,
) -> dict:
    params: dict[str, str] = {"resource": resource, **extra}
    if call in BULK_CALLS:
        start = datetime.now(timezone.utc) - timedelta(days=providers.ripestat_timeframe_days)
        params["max_rows"] = str(providers.ripestat_max_rows)
        params["starttime"] = start.strftime("%Y-%m-%dT%H:%M:%S")
    response = await client.get(f"{providers.ripestat_base_url}/{call}/data.json", params=params)
    response.raise_for_status()
    return response.json()


import json
import os
import time
from pathlib import Path
from typing import Awaitable, Callable

from netcheck.models import IxpPresence


def parse_asrank(payload: dict) -> tuple[int | None, int | None, int | None]:
    asn = ((payload.get("data") or {}).get("asn")) or {}
    cone = asn.get("cone") or {}
    return asn.get("rank"), cone.get("numberAsns"), cone.get("numberPrefixes")


def parse_cymru_origin(txt_record: str) -> dict[str, str]:
    parts = [part.strip() for part in txt_record.split("|")]
    if len(parts) < 5:
        return {}
    return {
        "asn": _as_label(parts[0].split()[0]),
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated_at": parts[4],
    }


def parse_peeringdb_net(payload: dict) -> tuple[str | None, str | None, int | None]:
    rows = payload.get("data") or []
    if not rows:
        return None, None, None
    row = rows[0]
    return row.get("info_type") or None, row.get("info_traffic") or None, row.get("id")


def parse_peeringdb_netixlan(payload: dict) -> list[IxpPresence]:
    return [
        IxpPresence(
            name=row.get("name", ""),
            city=row.get("city"),
            country=row.get("country"),
            speed_mbps=row.get("speed"),
        )
        for row in payload.get("data") or []
        if row.get("operational")
    ]


async def cached_json(
    cache_dir: Path,
    key: str,
    ttl_hours: int,
    fetch: Callable[[], Awaitable[dict]],
) -> dict:
    path = Path(cache_dir) / f"{key}.json"
    if path.exists() and (time.time() - path.stat().st_mtime) < ttl_hours * 3600:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    payload = await fetch()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)
    return payload
