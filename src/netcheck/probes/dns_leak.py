from __future__ import annotations

import ipaddress

from netcheck.models import AdapterLeakResult, DnsLeak

_LEAK_NOTE = (
    "This test only sees resolvers configured at the OS level. A browser using DoH "
    "or DoT bypasses them entirely and is not covered here."
)


def _unquote(text: str) -> str:
    return text.strip().strip('"')


def parse_akahelp(records: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for record in records:
        parts = [_unquote(part) for part in record.replace('" "', '"\t"').split("\t")]
        if len(parts) != 2:
            parts = [_unquote(p) for p in record.split(None, 1)]
        if len(parts) != 2 or not parts[0]:
            continue
        mapping[parts[0]] = parts[1]
    return mapping


def parse_myaddr(records: list[str]) -> str | None:
    for record in records:
        candidate = _unquote(record)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None


def detect_ecs_leak(akahelp: dict[str, str]) -> bool:
    ecs = akahelp.get("ecs", "").strip()
    if not ecs or ecs.startswith("0.0.0.0/0") or ecs.startswith("::/0"):
        return False
    return True


def build_adapter_result(
    adapter: str,
    resolvers: list[str],
    echoed_ip: str | None,
    echoed_asn: str | None,
    egress_asn: str | None,
) -> AdapterLeakResult:
    matches: bool | None = None
    if echoed_asn and egress_asn:
        matches = echoed_asn.upper() == egress_asn.upper()
    return AdapterLeakResult(
        adapter=adapter,
        configured_resolvers=list(resolvers),
        echoed_ip=echoed_ip,
        echoed_asn=echoed_asn,
        matches_egress_asn=matches,
    )


def build_dns_leak(results: list[AdapterLeakResult], ecs_leaked: bool) -> DnsLeak:
    leaking = [r.adapter for r in results if r.matches_egress_asn is False]
    parts: list[str] = []
    if leaking:
        parts.append(
            f"DNS queries from {', '.join(leaking)} resolve through a network outside the egress ASN."
        )
    else:
        parts.append("No adapter resolves DNS outside the egress ASN.")
    if ecs_leaked:
        parts.append("The resolver forwards your EDNS Client Subnet, exposing your network to authoritative servers.")
    parts.append(_LEAK_NOTE)
    return DnsLeak(per_adapter=results, ecs_leaked=ecs_leaked, note=" ".join(parts))


import asyncio

import dns.asyncresolver
import dns.exception

from netcheck.bgp import parse_cymru_origin
from netcheck.models import LocalNet

MYADDR_NAME = "o-o.myaddr.l.google.com"
AKAHELP_NAME = "whoami.ds.akahelp.net"


async def _txt(resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    return [b" ".join(record.strings).decode("utf-8", "replace") for record in answer]


def _resolver_for(server: str, timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.lifetime = timeout
    return resolver


async def echo_probe(resolver_ip: str, timeout: float) -> tuple[str | None, dict[str, str]]:
    resolver = _resolver_for(resolver_ip, timeout)
    myaddr, akahelp = await asyncio.gather(
        _txt(resolver, MYADDR_NAME), _txt(resolver, AKAHELP_NAME)
    )
    parsed = parse_akahelp(akahelp)
    return parse_myaddr(myaddr) or parsed.get("ns"), parsed


async def asn_for_ip(ip: str, zone: str, timeout: float) -> str | None:
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
    except AttributeError:
        return None
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    records = await _txt(resolver, f"{reversed_ip}.{zone}")
    for record in records:
        parsed = parse_cymru_origin(record)
        if parsed.get("asn"):
            return parsed["asn"]
    return None


async def collect_dns_leak(
    local: LocalNet,
    egress_asn: str | None,
    cymru_zone: str,
    timeout: float,
) -> DnsLeak:
    results: list[AdapterLeakResult] = []
    ecs_leaked = False
    for adapter, resolvers in local.dns_servers_per_adapter.items():
        if not resolvers:
            continue
        try:
            echoed_ip, akahelp = await echo_probe(resolvers[0], timeout)
        except dns.exception.DNSException:
            echoed_ip, akahelp = None, {}
        ecs_leaked = ecs_leaked or detect_ecs_leak(akahelp)
        echoed_asn = await asn_for_ip(echoed_ip, cymru_zone, timeout) if echoed_ip else None
        results.append(build_adapter_result(adapter, resolvers, echoed_ip, echoed_asn, egress_asn))
    return build_dns_leak(results, ecs_leaked)
