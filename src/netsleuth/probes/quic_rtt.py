from __future__ import annotations

import asyncio
import time

from netsleuth.models import QuicResult
from netsleuth.probes.latency import tcp_connect_rtt


def quic_verdict(quic_ok: bool, tcp_ok: bool) -> str:
    if quic_ok:
        return "ok"
    if tcp_ok:
        return "blocked"
    return "unreachable"


async def measure_quic(label: str, host: str, *, port: int = 443, timeout: float = 5.0) -> QuicResult:
    result = QuicResult(label=label, host=host, port=port)
    try:
        import aioquic  # noqa: F401
    except ImportError:
        result.error = "aioquic not installed"
        return result

    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import HandshakeCompleted

    class _HandshakeCapture(QuicConnectionProtocol):
        handshake_event: HandshakeCompleted | None = None

        def quic_event_received(self, event) -> None:
            if isinstance(event, HandshakeCompleted):
                self.handshake_event = event

    result.tcp_rtt_ms = await tcp_connect_rtt(host, port=port, timeout=timeout)

    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=host)

    async def _handshake() -> None:
        began = time.perf_counter()
        async with connect(
            host, port, configuration=configuration, create_protocol=_HandshakeCapture, wait_connected=True
        ) as protocol:
            result.handshake_ms = round((time.perf_counter() - began) * 1000.0, 3)
            event = protocol.handshake_event
            if event is not None:
                result.alpn = event.alpn_protocol
                result.session_resumed = event.session_resumed

    try:
        await asyncio.wait_for(_handshake(), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - a dead UDP/443 path is data, not control flow
        result.error = str(exc) or exc.__class__.__name__
    return result


async def quic_fanout(
    targets: list[tuple[str, str]], *, port: int, timeout: float, concurrency: int
) -> list[QuicResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(label: str, host: str) -> QuicResult:
        async with semaphore:
            return await measure_quic(label, host, port=port, timeout=timeout)

    return list(await asyncio.gather(*(_bounded(label, host) for label, host in targets)))
