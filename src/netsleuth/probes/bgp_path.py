from __future__ import annotations

import asyncio
import re

import httpx

from netsleuth.ip_geo import parse_cf_trace
from netsleuth.models import AnycastHop, PathDiversity
from netsleuth.probes.latency import tcp_connect_rtt
from netsleuth.speed import parse_server_timing_cfl4

_CF_RAY_RE = re.compile(r"-([A-Za-z]{2,4})$")

COLO_LOCATIONS: dict[str, tuple[str, str]] = {
    "DME": ("Moscow", "RU"),
    "SVO": ("Moscow", "RU"),
    "LED": ("Saint Petersburg", "RU"),
    "KJA": ("Krasnoyarsk", "RU"),
    "HEL": ("Helsinki", "FI"),
    "ARN": ("Stockholm", "SE"),
    "RIX": ("Riga", "LV"),
    "TLL": ("Tallinn", "EE"),
    "VNO": ("Vilnius", "LT"),
    "WAW": ("Warsaw", "PL"),
    "FRA": ("Frankfurt", "DE"),
    "AMS": ("Amsterdam", "NL"),
    "CDG": ("Paris", "FR"),
    "LHR": ("London", "GB"),
    "VIE": ("Vienna", "AT"),
    "PRG": ("Prague", "CZ"),
    "BUD": ("Budapest", "HU"),
    "OTP": ("Bucharest", "RO"),
    "SOF": ("Sofia", "BG"),
    "IST": ("Istanbul", "TR"),
    "KBP": ("Kyiv", "UA"),
    "ALA": ("Almaty", "KZ"),
    "TAS": ("Tashkent", "UZ"),
    "TBS": ("Tbilisi", "GE"),
    "EVN": ("Yerevan", "AM"),
    "DXB": ("Dubai", "AE"),
    "SIN": ("Singapore", "SG"),
    "NRT": ("Tokyo", "JP"),
    "LAX": ("Los Angeles", "US"),
    "IAD": ("Ashburn", "US"),
    "ORD": ("Chicago", "US"),
    "SEA": ("Seattle", "US"),
}


def parse_cf_ray(header: str | None) -> str | None:
    if not header:
        return None
    match = _CF_RAY_RE.search(header)
    if not match:
        return None
    return match.group(1).upper()


def colo_location(code: str | None) -> tuple[str | None, str | None]:
    if not code:
        return None, None
    return COLO_LOCATIONS.get(code.upper(), (None, None))


def detect_international_loop(client_country: str | None, edge_country: str | None) -> tuple[bool, list[str]]:
    if not client_country or not edge_country or edge_country == client_country:
        return False, []
    return True, [edge_country]


def build_path_diversity(client_country: str | None, hops: list[AnycastHop]) -> PathDiversity:
    if not hops:
        return PathDiversity(client_country=client_country, hops=[])

    international_loop = False
    detour_countries: list[str] = []
    for hop in hops:
        is_loop, countries = detect_international_loop(client_country, hop.edge_country)
        if is_loop:
            international_loop = True
            for country in countries:
                if country not in detour_countries:
                    detour_countries.append(country)

    if international_loop:
        note = (
            f"Anycast routed traffic through {', '.join(detour_countries)} "
            f"even though the client is in {client_country}."
        )
        note_ru = (
            f"Anycast завернул трафик через {', '.join(detour_countries)}, "
            f"хотя клиент находится в {client_country}."
        )
    else:
        note = "No international routing loop detected."
        note_ru = "Международной петли в маршруте не обнаружено."

    return PathDiversity(
        client_country=client_country,
        hops=hops,
        international_loop=international_loop,
        detour_countries=detour_countries,
        note=note,
        note_ru=note_ru,
    )


async def probe_edge(
    client: httpx.AsyncClient, target: str, *, timeout: float, source_ip: str | None = None
) -> AnycastHop:
    try:
        response = await client.get(f"https://{target}/cdn-cgi/trace", timeout=timeout)
    except httpx.HTTPError:
        return AnycastHop(target=target, source="none")

    client_rtt_ms = await tcp_connect_rtt(target, timeout=timeout, source_ip=source_ip)

    edge_colo = parse_cf_ray(response.headers.get("cf-ray"))
    edge_rtt_ms = None
    source = "none"

    if edge_colo:
        source = "cf_ray"
    else:
        cfl4 = parse_server_timing_cfl4(response.headers.get("server-timing", ""))
        if cfl4:
            edge_rtt_ms = cfl4.rtt_ms
            source = "server_timing"

    resolved_ip = None
    cf_trace = parse_cf_trace(response.text) if response.text else None
    if cf_trace:
        resolved_ip = cf_trace.ip
        if not edge_colo and cf_trace.colo:
            edge_colo = cf_trace.colo
            source = "cf_trace"

    edge_city, edge_country = colo_location(edge_colo)

    return AnycastHop(
        target=target,
        resolved_ip=resolved_ip,
        edge_colo=edge_colo,
        edge_city=edge_city,
        edge_country=edge_country,
        edge_rtt_ms=edge_rtt_ms,
        client_rtt_ms=client_rtt_ms,
        source=source,
    )


async def collect_path_diversity(
    client: httpx.AsyncClient,
    targets: list[tuple[str, str]],
    client_country: str | None,
    *,
    max_targets: int,
    timeout: float,
    source_ip: str | None = None,
) -> PathDiversity:
    coros = [
        probe_edge(client, host, timeout=timeout, source_ip=source_ip)
        for _label, host in targets[:max_targets]
    ]
    hops = await asyncio.gather(*coros)
    return build_path_diversity(client_country, list(hops))
