from __future__ import annotations

import asyncio
import socket
import time

from netsleuth.models import Capabilities, PingResult
from netsleuth.netinfo import choose_latency_backend
from netsleuth.stats import rtt_stats


def summarize_ping(
    label: str,
    host: str,
    resolved_ip: str | None,
    method: str,
    samples: list[float | None],
) -> PingResult:
    s = rtt_stats(samples)
    return PingResult(
        label=label,
        host=host,
        resolved_ip=resolved_ip,
        method=method,
        sent=s.sent,
        received=s.received,
        loss_pct=s.loss_pct,
        min_ms=s.min_ms,
        avg_ms=s.avg_ms,
        max_ms=s.max_ms,
        mdev_ms=s.mdev_ms,
        jitter_ms=s.jitter_ms,
        samples=samples,
    )


async def tcp_connect_rtt(
    host: str, port: int = 443, timeout: float = 2.0, source_ip: str | None = None
) -> float | None:
    began = time.perf_counter()
    local_addr = (source_ip, 0) if source_ip else None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, local_addr=local_addr), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return (time.perf_counter() - began) * 1000.0


async def _resolve(host: str) -> str | None:
    try:
        loop = asyncio.get_running_loop()
        res = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return res[0][4][0]
    except (OSError, IndexError):
        return None


async def _icmp_samples(
    host: str, count: int, interval: float, timeout: float, backend: str, source_ip: str | None = None
) -> list[float | None]:
    if backend == "icmp_win":
        from netsleuth.probes.icmp_win import ping_samples_win

        return await asyncio.to_thread(ping_samples_win, host, count, interval, timeout, source_ip)
    from icmplib import async_ping

    privileged = backend == "icmp_raw"
    host_result = await async_ping(
        host, count=count, interval=interval, timeout=timeout, privileged=privileged, source=source_ip
    )
    samples: list[float | None] = list(host_result.rtts)
    samples.extend([None] * (count - len(samples)))
    return samples


async def ping_host(
    host: str,
    label: str,
    count: int,
    interval: float,
    timeout: float,
    backend: str,
    source_ip: str | None = None,
) -> PingResult:
    resolved = await _resolve(host)
    if backend in ("icmp_win", "icmp_dgram", "icmp_raw"):
        try:
            samples = await _icmp_samples(host, count, interval, timeout, backend, source_ip)
            return summarize_ping(label, host, resolved, backend, samples)
        except Exception:
            backend = "tcp"
    samples = []
    for index in range(count):
        if index:
            await asyncio.sleep(interval)
        samples.append(await tcp_connect_rtt(host, timeout=timeout, source_ip=source_ip))
    return summarize_ping(label, host, resolved, "tcp", samples)


async def ping_fanout(
    hosts: list[tuple[str, str]],
    caps: Capabilities,
    count: int,
    interval: float,
    timeout: float,
    source_ip: str | None = None,
) -> list[PingResult]:
    backend = choose_latency_backend(caps)
    return list(
        await asyncio.gather(
            *(ping_host(host, label, count, interval, timeout, backend, source_ip) for label, host in hosts)
        )
    )
