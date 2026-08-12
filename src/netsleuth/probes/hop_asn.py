from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.reversename

from netsleuth.bgp import parse_cymru_origin
from netsleuth.models import TraceResult

_NON_ROUTABLE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not any(addr in net for net in _NON_ROUTABLE)


def cymru_query_name(ip: str | None, origin_zone: str, origin6_zone: str) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not _is_public(addr):
        return None
    if addr.version == 4:
        reversed_octets = ".".join(reversed(ip.split(".")))
        return f"{reversed_octets}.{origin_zone}"
    nibbles = addr.exploded.replace(":", "")
    reversed_nibbles = ".".join(reversed(nibbles))
    return f"{reversed_nibbles}.{origin6_zone}"


def parse_cymru_asname(txt: str) -> tuple[str | None, str | None]:
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 5:
        return None, None
    return (parts[4] or None), (parts[1] or None)


async def _txt(resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    return [b" ".join(record.strings).decode("utf-8", "replace") for record in answer]


async def _ptr(resolver: dns.asyncresolver.Resolver, ip: str) -> str | None:
    try:
        answer = await resolver.resolve(dns.reversename.from_address(ip), "PTR")
    except (dns.exception.DNSException, ValueError):
        return None
    return str(answer[0]).rstrip(".") if len(answer) else None


async def lookup_hop(
    ip: str | None,
    *,
    origin_zone: str,
    origin6_zone: str,
    asn_zone: str,
    timeout: float,
) -> dict[str, str | None]:
    query_name = cymru_query_name(ip, origin_zone, origin6_zone)
    if query_name is None:
        return {}
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    origin_records, ptr_name = await asyncio.gather(_txt(resolver, query_name), _ptr(resolver, ip))
    result: dict[str, str | None] = {}
    if ptr_name:
        result["reverse_dns"] = ptr_name
    origin: dict[str, str] = {}
    for record in origin_records:
        parsed = parse_cymru_origin(record)
        if parsed.get("asn"):
            origin = parsed
            break
    if not origin.get("asn"):
        return result
    asn_number = origin["asn"].removeprefix("AS")
    as_name: str | None = None
    country = origin.get("country")
    for record in await _txt(resolver, f"AS{asn_number}.{asn_zone}"):
        name, name_country = parse_cymru_asname(record)
        if name:
            as_name, country = name, (name_country or country)
            break
    result.update({"asn": origin["asn"], "as_name": as_name, "country": country})
    return result


async def enrich_hops(
    traces: list[TraceResult],
    *,
    origin_zone: str,
    origin6_zone: str,
    asn_zone: str,
    timeout: float,
    concurrency: int = 8,
) -> None:
    hops_by_ip: dict[str, list] = {}
    for trace in traces:
        for hop in trace.hops:
            if hop.ip:
                hops_by_ip.setdefault(hop.ip, []).append(hop)
    if not hops_by_ip:
        return
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(ip: str) -> tuple[str, dict[str, str | None]]:
        async with semaphore:
            return ip, await lookup_hop(
                ip, origin_zone=origin_zone, origin6_zone=origin6_zone, asn_zone=asn_zone, timeout=timeout
            )

    results = await asyncio.gather(*(_bounded(ip) for ip in hops_by_ip))
    for ip, info in results:
        if not info:
            continue
        for hop in hops_by_ip[ip]:
            if info.get("asn"):
                hop.asn = info["asn"]
                hop.as_name = info.get("as_name")
                hop.country = info.get("country")
            if info.get("reverse_dns") and not hop.reverse_dns:
                hop.reverse_dns = info["reverse_dns"]
