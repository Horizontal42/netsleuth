from __future__ import annotations

import ipaddress
import re

from netcheck.models import CfTrace, IpGeo

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
