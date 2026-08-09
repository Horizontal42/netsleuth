from __future__ import annotations

import asyncio
import ssl
import time

from netsleuth.models import TlsResult
from netsleuth.probes.latency import tcp_connect_rtt


def split_timings(
    tcp_rtt_ms: float | None, tls_total_ms: float | None, ttfb_ms: float | None
) -> tuple[float | None, float | None, float | None]:
    handshake_ms = None
    if tcp_rtt_ms is not None and tls_total_ms is not None:
        handshake_ms = max(0.0, tls_total_ms - tcp_rtt_ms)
    return tcp_rtt_ms, handshake_ms, ttfb_ms


def cpu_bound_ratio(tls_handshake_ms: float | None, tcp_rtt_ms: float | None) -> float | None:
    if tls_handshake_ms is None or not tcp_rtt_ms:
        return None
    return tls_handshake_ms / tcp_rtt_ms


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx


async def measure_tls(
    label: str,
    host: str,
    *,
    port: int = 443,
    timeout: float = 3.0,
    source_ip: str | None = None,
) -> TlsResult:
    result = TlsResult(label=label, host=host, port=port)
    try:
        tcp_rtt_ms = await tcp_connect_rtt(host, port=port, timeout=timeout, source_ip=source_ip)
        result.tcp_rtt_ms = tcp_rtt_ms

        local_addr = (source_ip, 0) if source_ip else None
        began = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=tls_context(), server_hostname=host, local_addr=local_addr
            ),
            timeout=timeout,
        )
        tls_total_ms = (time.perf_counter() - began) * 1000.0

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            result.tls_version = ssl_object.version()
            cipher = ssl_object.cipher()
            result.cipher = cipher[0] if cipher else None
            result.alpn = ssl_object.selected_alpn_protocol()

        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        began_ttfb = time.perf_counter()
        writer.write(request)
        await writer.drain()
        await asyncio.wait_for(reader.read(1), timeout=timeout)
        ttfb_ms = (time.perf_counter() - began_ttfb) * 1000.0

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        _tcp_rtt_ms, handshake_ms, ttfb_ms = split_timings(tcp_rtt_ms, tls_total_ms, ttfb_ms)
        result.tls_handshake_ms = handshake_ms
        result.ttfb_ms = ttfb_ms
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        result.error = str(exc) or exc.__class__.__name__
    return result


async def tls_fanout(
    targets: list[tuple[str, str]],
    *,
    port: int,
    timeout: float,
    concurrency: int,
    source_ip: str | None = None,
) -> list[TlsResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(label: str, host: str) -> TlsResult:
        async with semaphore:
            return await measure_tls(label, host, port=port, timeout=timeout, source_ip=source_ip)

    return list(await asyncio.gather(*(_bounded(label, host) for label, host in targets)))
