from __future__ import annotations

import asyncio
import ipaddress
import time

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import httpx

from netsleuth.models import DnsAdvanced, ResolverProbe

_A_RECORD_TYPE = 1
_AAAA_RECORD_TYPE = 28


def parse_doh_json(payload: dict) -> list[str]:
    if payload.get("Status") != 0:
        return []
    answers = payload.get("Answer") or []
    return [
        record["data"]
        for record in answers
        if record.get("type") in (_A_RECORD_TYPE, _AAAA_RECORD_TYPE)
    ]


def is_suspicious_answer(addr: str) -> bool:
    if addr == "0.0.0.0":
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_reserved


def compare_answers(system_probe: ResolverProbe, doh_probes: list[ResolverProbe]) -> list[str]:
    divergences: list[str] = []
    system_set = set(system_probe.answers)
    for doh_probe in doh_probes:
        doh_set = set(doh_probe.answers)
        if system_set == doh_set:
            continue
        suspicious = detect_poisoning(system_probe, [doh_probe])
        divergences.append(
            f"{system_probe.query_name}: system={sorted(system_set)} "
            f"vs {doh_probe.name}={sorted(doh_set)} (suspicious={suspicious})"
        )
    return divergences


def detect_poisoning(system_probe: ResolverProbe, doh_probes: list[ResolverProbe]) -> bool:
    system_suspicious = any(is_suspicious_answer(a) for a in system_probe.answers)
    if not system_suspicious:
        return False
    return any(
        any(not is_suspicious_answer(a) for a in doh_probe.answers) for doh_probe in doh_probes
    )


def detect_transparent_proxy(bogus_probe: ResolverProbe) -> tuple[bool | None, str]:
    if bogus_probe.error is None and bogus_probe.answers:
        return True, "A response was received from the bogus resolver IP: transparent DNS proxy detected."
    return False, "No response from the bogus resolver IP (timeout): transparent DNS proxy not detected."


async def resolve_system(name: str, timeout: float) -> ResolverProbe:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    start = time.monotonic()
    try:
        answer = await resolver.resolve(name, "A")
        elapsed_ms = (time.monotonic() - start) * 1000
        answers = [rdata.address for rdata in answer]
        return ResolverProbe(
            name="system",
            kind="system",
            query_name=name,
            answers=answers,
            elapsed_ms=elapsed_ms,
        )
    except dns.exception.DNSException as exc:
        return ResolverProbe(name="system", kind="system", query_name=name, error=str(exc))


async def resolve_doh(
    client: httpx.AsyncClient,
    name: str,
    url: str,
    query_name: str,
    timeout: float,
) -> ResolverProbe:
    start = time.monotonic()
    try:
        response = await client.get(
            url,
            params={"name": query_name, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
        )
        response.raise_for_status()
        elapsed_ms = (time.monotonic() - start) * 1000
        answers = parse_doh_json(response.json())
        return ResolverProbe(
            name=name,
            kind="doh",
            endpoint=url,
            query_name=query_name,
            answers=answers,
            elapsed_ms=elapsed_ms,
        )
    except httpx.HTTPError as exc:
        return ResolverProbe(name=name, kind="doh", endpoint=url, query_name=query_name, error=str(exc))


async def probe_bogus_resolver(ip: str, name: str, timeout: float) -> ResolverProbe:
    query = dns.message.make_query(name, "A")
    try:
        response = await dns.asyncquery.udp(query, ip, timeout=timeout)
        answers = [
            rdata.address
            for rrset in response.answer
            for rdata in rrset
            if rdata.rdtype == 1
        ]
        return ResolverProbe(name="bogus", kind="system", query_name=name, answers=answers)
    except dns.exception.Timeout:
        return ResolverProbe(name="bogus", kind="system", query_name=name, error="timeout")
    except (dns.exception.DNSException, OSError) as exc:
        return ResolverProbe(name="bogus", kind="system", query_name=name, error=str(exc))


async def collect_dns_advanced(
    client: httpx.AsyncClient,
    control_names: list[str],
    doh_endpoints,
    bogus_resolver_ip: str,
    bogus_probe_name: str,
    timeout: float,
) -> DnsAdvanced:
    system_probes = list(await asyncio.gather(*(resolve_system(name, timeout) for name in control_names)))
    doh_tasks = [
        resolve_doh(client, ep.name, ep.url, name, timeout)
        for name in control_names
        for ep in doh_endpoints
    ]
    doh_probes = list(await asyncio.gather(*doh_tasks))

    divergences: list[str] = []
    for system_probe in system_probes:
        matching_doh = [p for p in doh_probes if p.query_name == system_probe.query_name]
        divergences.extend(compare_answers(system_probe, matching_doh))

    system_times = [p.elapsed_ms for p in system_probes if p.elapsed_ms is not None]
    doh_times = [p.elapsed_ms for p in doh_probes if p.elapsed_ms is not None]
    system_avg_ms = sum(system_times) / len(system_times) if system_times else None
    doh_avg_ms = sum(doh_times) / len(doh_times) if doh_times else None

    bogus_probe = await probe_bogus_resolver(bogus_resolver_ip, bogus_probe_name, timeout)
    transparent_proxy, transparent_proxy_detail = detect_transparent_proxy(bogus_probe)

    note = (
        "Compared system resolver answers and timing against DoH resolvers on control names, "
        "and probed a bogus resolver IP to check for a transparent DNS proxy."
    )
    note_ru = (
        "Сравнили ответы и время системного резолвера с DoH-резолверами на контрольных именах, "
        "а также проверили фиктивный IP резолвера на признаки прозрачного DNS-прокси."
    )

    return DnsAdvanced(
        probes=system_probes + doh_probes,
        system_avg_ms=system_avg_ms,
        doh_avg_ms=doh_avg_ms,
        divergences=divergences,
        transparent_proxy=transparent_proxy,
        transparent_proxy_detail=transparent_proxy_detail,
        note=note,
        note_ru=note_ru,
    )
