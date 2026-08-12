from __future__ import annotations

import asyncio
from dataclasses import fields as dataclass_fields
import ipaddress
import re

import httpx

from netsleuth.config import Providers
from netsleuth.models import CfTrace, IpGeo

_AS_PREFIX_RE = re.compile(r"^AS(\d+)\s*(?P<name>.*)$", re.IGNORECASE)


def _as_number(value: object) -> str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    match = _AS_PREFIX_RE.match(text)
    if match:
        return f"AS{match.group(1)}"
    if text.isdigit():
        return f"AS{text}"
    return None


def _as_label(value: object) -> str | None:
    match = _AS_PREFIX_RE.match(str(value or ""))
    name = (match.group("name") if match else "").strip()
    return name or None


def _ip_version(ip: str | None) -> int | None:
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def classify_ip_type(mobile: bool, proxy: bool, hosting: bool, known: bool) -> str:
    if not known:
        return "unknown"
    if mobile:
        return "mobile"
    if hosting or proxy:
        return "hosting"
    return "residential"


def provider_flags(payload: dict) -> dict[str, bool]:
    if payload.get("status") != "success":
        return {}
    return {
        "mobile": bool(payload.get("mobile")),
        "proxy": bool(payload.get("proxy")),
        "hosting": bool(payload.get("hosting")),
    }


def normalize_ip_api(payload: dict) -> IpGeo:
    if payload.get("status") != "success":
        return IpGeo(ip=payload.get("query"), ip_version=_ip_version(payload.get("query")))
    ip = payload.get("query")
    return IpGeo(
        ip=ip,
        ip_version=_ip_version(ip),
        reverse_dns=payload.get("reverse") or None,
        asn=_as_number(payload.get("as")),
        as_name=_as_label(payload.get("as")),
        org=payload.get("org") or payload.get("isp") or None,
        country=payload.get("country"),
        country_code=payload.get("countryCode"),
        city=payload.get("city"),
        lat=payload.get("lat"),
        lon=payload.get("lon"),
        timezone=payload.get("timezone"),
        ip_type=classify_ip_type(
            bool(payload.get("mobile")), bool(payload.get("proxy")), bool(payload.get("hosting")), True
        ),
        sources={"provider": "ip-api"},
    )


def normalize_freeipapi(payload: dict) -> IpGeo:
    ip = payload.get("ipAddress")
    return IpGeo(
        ip=ip,
        ip_version=payload.get("ipVersion") or _ip_version(ip),
        asn=_as_number(payload.get("asn")),
        org=payload.get("asnOrganization") or None,
        country=payload.get("countryName"),
        country_code=payload.get("countryCode"),
        city=payload.get("cityName"),
        lat=payload.get("latitude"),
        lon=payload.get("longitude"),
        ip_type=classify_ip_type(False, bool(payload.get("isProxy")), False, True),
        sources={"provider": "freeipapi"},
    )


def normalize_ipinfo(payload: dict) -> IpGeo:
    lat = lon = None
    loc = payload.get("loc")
    if isinstance(loc, str) and "," in loc:
        raw_lat, _, raw_lon = loc.partition(",")
        try:
            lat, lon = float(raw_lat), float(raw_lon)
        except ValueError:
            lat = lon = None
    ip = payload.get("ip")
    return IpGeo(
        ip=ip,
        ip_version=_ip_version(ip),
        reverse_dns=payload.get("hostname") or None,
        asn=_as_number(payload.get("org")),
        as_name=_as_label(payload.get("org")),
        org=_as_label(payload.get("org")),
        country_code=payload.get("country"),
        city=payload.get("city"),
        lat=lat,
        lon=lon,
        timezone=payload.get("timezone"),
        sources={"provider": "ipinfo"},
    )


def normalize_ipwhois(payload: dict) -> IpGeo:
    if not payload.get("success", True):
        return IpGeo(ip=payload.get("ip"))
    connection = payload.get("connection") or {}
    timezone = payload.get("timezone") or {}
    ip = payload.get("ip")
    return IpGeo(
        ip=ip,
        ip_version=_ip_version(ip),
        asn=_as_number(connection.get("asn")),
        as_name=connection.get("isp") or None,
        org=connection.get("org") or None,
        country=payload.get("country"),
        country_code=payload.get("country_code"),
        city=payload.get("city"),
        lat=payload.get("latitude"),
        lon=payload.get("longitude"),
        timezone=timezone.get("id") if isinstance(timezone, dict) else timezone,
        sources={"provider": "ipwho.is"},
    )


def normalize_ripestat_network_info(payload: dict) -> IpGeo:
    data = payload.get("data") or {}
    asns = data.get("asns") or []
    return IpGeo(asn=_as_number(asns[0]) if asns else None, sources={"asn": "ripestat"})


def parse_cf_trace(text: str) -> CfTrace:
    raw: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        raw[key.strip()] = value.strip()
    return CfTrace(
        ip=raw.get("ip"),
        colo=raw.get("colo"),
        loc=raw.get("loc"),
        warp=raw.get("warp"),
        gateway=raw.get("gateway"),
        rbi=raw.get("rbi"),
        raw=raw,
    )


_MERGE_SKIP = {"sources", "ip_type"}


def merge_geo(candidates: list[tuple[str, IpGeo]]) -> IpGeo:
    merged = IpGeo()
    sources: dict[str, str] = {}
    fields = dataclass_fields(IpGeo)
    for name, geo in candidates:
        for f in fields:
            if f.name in _MERGE_SKIP:
                continue
            if getattr(merged, f.name) is not None:
                continue
            value = getattr(geo, f.name)
            if value in (None, ""):
                continue
            setattr(merged, f.name, value)
            sources[f.name] = name
        if merged.ip_type == "unknown" and geo.ip_type != "unknown":
            merged.ip_type = geo.ip_type
            sources["ip_type"] = name
    merged.sources = sources
    return merged


def dual_stack_mismatch(v4: IpGeo | None, v6: IpGeo | None) -> tuple[str, str] | None:
    if v4 is None or v6 is None or not v4.asn or not v6.asn:
        return None
    if v4.asn == v6.asn and (v4.country_code or "") == (v6.country_code or ""):
        return None
    en = (
        f"IPv4 egress {v4.ip} is {v4.asn} ({v4.country_code}) but IPv6 egress {v6.ip} "
        f"is {v6.asn} ({v6.country_code}); the two stacks leave through different networks."
    )
    ru = (
        f"Исходящий IPv4 {v4.ip} — это {v4.asn} ({v4.country_code}), а исходящий IPv6 {v6.ip} — "
        f"{v6.asn} ({v6.country_code}); два стека выходят через разные сети."
    )
    return en, ru


async def _json(client: httpx.AsyncClient, url: str, **kwargs) -> dict:
    response = await client.get(url, **kwargs)
    response.raise_for_status()
    return response.json()


async def _text(client: httpx.AsyncClient, url: str) -> str:
    response = await client.get(url)
    response.raise_for_status()
    return response.text


async def gather_identity(
    client: httpx.AsyncClient,
    providers: Providers,
    ip: str | None = None,
    ipinfo_token: str | None = None,
) -> tuple[IpGeo, CfTrace | None, dict[str, bool], dict[str, object]]:
    suffix = ip or ""
    headers = {"Authorization": f"Bearer {ipinfo_token}"} if ipinfo_token else {}
    calls = {
        "cf-trace": _text(client, providers.cf_trace_url),
        "ip-api": _json(client, f"{providers.ip_api_url}{suffix}"),
        "freeipapi": _json(client, f"{providers.freeipapi_url}{suffix}"),
        "ipinfo": _json(client, f"{providers.ipinfo_url}{suffix}json", headers=headers),
        "ipwho.is": _json(client, f"{providers.ipwhois_url}{suffix}"),
    }
    settled = await asyncio.gather(*calls.values(), return_exceptions=True)
    payloads = dict(zip(calls.keys(), settled))

    raw: dict[str, object] = {k: v for k, v in payloads.items() if not isinstance(v, BaseException)}
    cf = parse_cf_trace(payloads["cf-trace"]) if isinstance(payloads["cf-trace"], str) else None
    flags = provider_flags(payloads["ip-api"]) if isinstance(payloads["ip-api"], dict) else {}

    candidates: list[tuple[str, IpGeo]] = []
    if cf and not ip:
        # cf-trace can only ever describe the machine making the request, never an
        # arbitrary target — folding it in during a target lookup would splice this
        # host's own IP onto the target's asn/geo fields from the other providers.
        candidates.append(("cf-trace", IpGeo(ip=cf.ip, country_code=cf.loc, sources={})))
    for name, normalizer in (
        ("ip-api", normalize_ip_api),
        ("freeipapi", normalize_freeipapi),
        ("ipinfo", normalize_ipinfo),
        ("ipwho.is", normalize_ipwhois),
    ):
        payload = payloads[name]
        if isinstance(payload, dict):
            candidates.append((name, normalizer(payload)))

    merged = merge_geo(candidates)
    if merged.ip:
        try:
            network_info = await _json(
                client, f"{providers.ripestat_base_url}/network-info/data.json", params={"resource": merged.ip}
            )
        except (httpx.HTTPError, ValueError):
            network_info = None
        if network_info:
            raw["ripestat-network-info"] = network_info
            authoritative = normalize_ripestat_network_info(network_info)
            if authoritative.asn:
                merged.asn = authoritative.asn
                merged.sources["asn"] = "ripestat"
    return merged, cf, flags, raw
