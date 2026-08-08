from __future__ import annotations

import asyncio
import socket
import time

from netcheck.models import Capabilities, PingResult
from netcheck.netinfo import choose_latency_backend
from netcheck.stats import rtt_stats


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


async def tcp_connect_rtt(host: str, port: int = 443, timeout: float = 2.0) -> float | None:
    began = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return (time.perf_counter() - began) * 1000.0


def _resolve(host: str) -> str | None:
    try:
        return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
    except (OSError, IndexError):
        return None


async def _icmp_samples(host: str, count: int, interval: float, timeout: float, backend: str) -> list[float | None]:
    if backend == "icmp_win":
        from netcheck.probes.icmp_win import ping_samples_win

        return await asyncio.to_thread(ping_samples_win, host, count, interval, timeout)
    from icmplib import async_ping

    privileged = backend == "icmp_raw"
    host_result = await async_ping(
        host, count=count, interval=interval, timeout=timeout, privileged=privileged
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
) -> PingResult:
    resolved = _resolve(host)
    if backend in ("icmp_win", "icmp_dgram", "icmp_raw"):
        try:
            samples = await _icmp_samples(host, count, interval, timeout, backend)
            return summarize_ping(label, host, resolved, backend, samples)
        except Exception:
            backend = "tcp"
    samples = []
    for index in range(count):
        if index:
            await asyncio.sleep(interval)
        samples.append(await tcp_connect_rtt(host, timeout=timeout))
    return summarize_ping(label, host, resolved, "tcp", samples)


async def ping_fanout(
    hosts: list[tuple[str, str]],
    caps: Capabilities,
    count: int,
    interval: float,
    timeout: float,
) -> list[PingResult]:
    backend = choose_latency_backend(caps)
    return list(
        await asyncio.gather(
            *(ping_host(host, label, count, interval, timeout, backend) for label, host in hosts)
        )
    )
