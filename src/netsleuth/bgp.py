from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import httpx

from netsleuth.config import Providers
from netsleuth.models import BgpEvent

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
from dataclasses import dataclass
from typing import Awaitable, Callable

from netsleuth.models import IxpPresence


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
    age = max(0.0, time.time() - path.stat().st_mtime) if path.exists() else None
    if age is not None and age < ttl_hours * 3600:
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


from netsleuth.models import BgpIntel


@dataclass
class BgpContext:
    asn: str
    overview: dict
    neighbours: dict
    prefixes: dict
    updates: dict
    asrank: dict | None
    pdb_net: dict | None
    pdb_ixlan: dict | None
    timeframe_days: int


def build_bgp_intel(ctx: BgpContext) -> BgpIntel:
    info = parse_as_overview(ctx.overview)
    upstreams, peers, downstreams = parse_asn_neighbours(ctx.neighbours)
    announced, v4, v6 = parse_announced_prefixes(ctx.prefixes)
    events = parse_bgp_updates(ctx.updates)
    rank, cone_asns, cone_prefixes = parse_asrank(ctx.asrank) if ctx.asrank else (None, None, None)
    info_type, traffic, _net_id = parse_peeringdb_net(ctx.pdb_net) if ctx.pdb_net else (None, None, None)
    return BgpIntel(
        asn=ctx.asn,
        holder=info["holder"],
        registry=info["registry"],
        allocated_at=info["allocated_at"],
        upstreams=upstreams,
        peers=peers,
        downstreams=downstreams,
        announced_prefixes=announced,
        prefix_count_v4=v4,
        prefix_count_v6=v6,
        flaps=events,
        stability=classify_stability(events, ctx.timeframe_days),
        ixps=parse_peeringdb_netixlan(ctx.pdb_ixlan) if ctx.pdb_ixlan else [],
        pdb_info_type=info_type,
        pdb_traffic=traffic,
        asrank=rank,
        cone_asns=cone_asns,
        cone_prefixes=cone_prefixes,
    )


import asyncio

_ASRANK_QUERY = """
query ASN($asn: String!) {
  asn(asn: $asn) {
    asn
    rank
    asnName
    organization { orgName }
    cone { numberAsns numberPrefixes numberAddresses }
    asnDegree { provider peer customer total }
  }
}
"""


async def collect_bgp(
    client: httpx.AsyncClient,
    providers: Providers,
    cache_dir: Path,
    asn: str,
    peeringdb_key: str | None = None,
) -> tuple[BgpIntel, dict[str, object]]:
    number = asn.upper().removeprefix("AS")

    async def _asrank() -> dict:
        response = await client.post(
            providers.asrank_url, json={"query": _ASRANK_QUERY, "variables": {"asn": number}}
        )
        response.raise_for_status()
        return response.json()

    async def _pdb(endpoint: str, **params) -> dict:
        headers = {"Authorization": f"Api-Key {peeringdb_key}"} if peeringdb_key else {}
        response = await client.get(
            f"{providers.peeringdb_base_url}/{endpoint}", params=params, headers=headers
        )
        response.raise_for_status()
        return response.json()

    settled = await asyncio.gather(
        ripestat(client, providers, "as-overview", asn),
        ripestat(client, providers, "asn-neighbours", asn),
        ripestat(client, providers, "announced-prefixes", asn),
        ripestat(client, providers, "bgp-updates", asn),
        _asrank(),
        cached_json(cache_dir, f"pdb-net-{number}", providers.peeringdb_cache_hours, lambda: _pdb("net", asn=number)),
        return_exceptions=True,
    )
    overview, neighbours, prefixes, updates, asrank, pdb_net = [
        None if isinstance(item, BaseException) else item for item in settled
    ]

    pdb_ixlan = None
    if pdb_net:
        _, _, net_id = parse_peeringdb_net(pdb_net)
        if net_id:
            try:
                pdb_ixlan = await cached_json(
                    cache_dir,
                    f"pdb-netixlan-{net_id}",
                    providers.peeringdb_cache_hours,
                    lambda: _pdb("netixlan", net_id=net_id),
                )
            except httpx.HTTPError:
                pdb_ixlan = None

    intel = build_bgp_intel(
        BgpContext(
            asn=asn,
            overview=overview or {},
            neighbours=neighbours or {},
            prefixes=prefixes or {},
            updates=updates or {},
            asrank=asrank,
            pdb_net=pdb_net,
            pdb_ixlan=pdb_ixlan,
            timeframe_days=providers.ripestat_timeframe_days,
        )
    )
    raw = {
        "ripestat-as-overview": overview,
        "ripestat-asn-neighbours": neighbours,
        "ripestat-announced-prefixes": prefixes,
        "ripestat-bgp-updates": updates,
        "caida-asrank": asrank,
        "peeringdb-net": pdb_net,
        "peeringdb-netixlan": pdb_ixlan,
    }
    return intel, {k: v for k, v in raw.items() if v is not None}
