from __future__ import annotations

import asyncio
import ipaddress

from netsleuth.models import Capabilities, PrefixBenchmark, PrefixProbe
from netsleuth.netinfo import choose_latency_backend
from netsleuth.probes.latency import ping_host

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def first_host(prefix: str, offset: int = 1) -> str | None:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    if network.version == 4 and network.prefixlen >= 31:
        return None
    try:
        return str(network[offset])
    except IndexError:
        return None


def select_prefixes(prefixes: list[str], *, limit: int, family: int = 4) -> list[str]:
    seen: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in prefixes:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if network.version != family:
            continue
        if (
            network.is_private
            or network.is_reserved
            or network.is_multicast
            or network.is_loopback
            or network.is_link_local
        ):
            continue
        if network.version == 4 and network.overlaps(_CGNAT):
            continue
        if network in seen:
            continue
        seen.add(network)
        networks.append(network)
    networks.sort(key=lambda n: n.network_address)
    return [str(n) for n in networks[:limit]]


def _is_ranked_reachable(probe: PrefixProbe) -> bool:
    return probe.reachable and probe.avg_ms is not None


def rank(results: list[PrefixProbe]) -> list[PrefixProbe]:
    reachable = sorted((p for p in results if _is_ranked_reachable(p)), key=lambda p: p.avg_ms)
    unreachable = [p for p in results if not _is_ranked_reachable(p)]
    return reachable + unreachable


def summarize(asn: str | None, announced_count: int, results: list[PrefixProbe]) -> PrefixBenchmark:
    reachable = [p for p in results if _is_ranked_reachable(p)]
    best = worst = spread_ms = None
    if reachable:
        best_probe = min(reachable, key=lambda p: p.avg_ms)
        worst_probe = max(reachable, key=lambda p: p.avg_ms)
        best = best_probe.prefix
        worst = worst_probe.prefix
        if len(reachable) >= 2:
            spread_ms = worst_probe.avg_ms - best_probe.avg_ms
    return PrefixBenchmark(
        asn=asn,
        prefixes_announced=announced_count,
        prefixes_probed=len(results),
        method="icmp" if results else "none",
        results=rank(results),
        best=best,
        worst=worst,
        spread_ms=spread_ms,
    )


async def benchmark_prefixes(
    prefixes: list[str],
    caps: Capabilities,
    *,
    limit: int,
    count: int,
    interval: float,
    timeout: float,
    concurrency: int,
    offset: int = 1,
    family: int = 4,
    source_ip: str | None = None,
) -> PrefixBenchmark:
    selected = select_prefixes(prefixes, limit=limit, family=family)
    hosts = [(prefix, first_host(prefix, offset)) for prefix in selected]
    hosts = [(prefix, host) for prefix, host in hosts if host is not None]
    backend = choose_latency_backend(caps)
    semaphore = asyncio.Semaphore(concurrency)

    async def _probe(prefix: str, host: str) -> PrefixProbe:
        result = await ping_host(host, prefix, count, interval, timeout, backend, source_ip, semaphore)
        return PrefixProbe(
            prefix=prefix,
            probe_ip=host,
            avg_ms=result.avg_ms,
            loss_pct=result.loss_pct,
            reachable=result.received > 0,
        )

    results = list(await asyncio.gather(*(_probe(prefix, host) for prefix, host in hosts)))
    return summarize(None, len(prefixes), results)
