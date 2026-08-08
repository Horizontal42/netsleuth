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
