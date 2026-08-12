from __future__ import annotations

import asyncio
import hashlib
import ssl
import time
from datetime import datetime, timezone

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


def tls_context(verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx


def fingerprint_verdict(host: str, actual_sha256: str | None, pins: dict[str, str]) -> str:
    pin = pins.get(host)
    if not pin:
        return "unpinned"
    if actual_sha256 is None:
        return "mismatch"
    normalized_pin = pin.replace(":", "").strip().lower()
    normalized_actual = actual_sha256.replace(":", "").strip().lower()
    return "match" if normalized_pin == normalized_actual else "mismatch"


def cert_name(rdn_sequence: tuple | None) -> str | None:
    if not rdn_sequence:
        return None
    parts = [f"{key}={value}" for rdn in rdn_sequence for key, value in rdn]
    return ", ".join(parts) or None


def days_remaining(not_after: str | None, now: datetime | None = None) -> int | None:
    if not not_after:
        return None
    try:
        expires_ts = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None
    expires = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
    return (expires - (now or datetime.now(timezone.utc))).days


async def measure_tls(
    label: str,
    host: str,
    *,
    port: int = 443,
    timeout: float = 3.0,
    source_ip: str | None = None,
    verify: bool = True,
    pins: dict[str, str] | None = None,
) -> TlsResult:
    result = TlsResult(label=label, host=host, port=port)
    pins = pins or {}
    try:
        tcp_rtt_ms = await tcp_connect_rtt(host, port=port, timeout=timeout, source_ip=source_ip)
        result.tcp_rtt_ms = tcp_rtt_ms

        local_addr = (source_ip, 0) if source_ip else None

        async def _connect(do_verify: bool):
            return await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=tls_context(verify=do_verify), server_hostname=host, local_addr=local_addr
                ),
                timeout=timeout,
            )

        began = time.perf_counter()
        cert_verified = verify
        try:
            reader, writer = await _connect(verify)
        except ssl.SSLCertVerificationError:
            if not verify:
                raise
            # The failed handshake's time is not representative of a real connection;
            # only the successful (unverified) attempt's duration feeds tls_handshake_ms.
            began = time.perf_counter()
            reader, writer = await _connect(False)
            cert_verified = False
        tls_total_ms = (time.perf_counter() - began) * 1000.0
        result.cert_verified = cert_verified
        result.resolved_ip = (writer.get_extra_info("peername") or (None,))[0]

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            result.tls_version = ssl_object.version()
            cipher = ssl_object.cipher()
            result.cipher = cipher[0] if cipher else None
            result.alpn = ssl_object.selected_alpn_protocol()
            der = ssl_object.getpeercert(binary_form=True)
            if der:
                result.cert_sha256 = hashlib.sha256(der).hexdigest()
                result.pin_verdict = fingerprint_verdict(host, result.cert_sha256, pins)
            if cert_verified:
                # getpeercert() only returns the parsed dict for a chain that
                # actually validated -- under CERT_NONE it is always {}.
                parsed = ssl_object.getpeercert() or {}
                result.cert_subject = cert_name(parsed.get("subject"))
                result.cert_issuer = cert_name(parsed.get("issuer"))
                result.cert_not_after = parsed.get("notAfter")
                result.cert_days_remaining = days_remaining(result.cert_not_after)

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
    verify: bool = True,
    pins: dict[str, str] | None = None,
) -> list[TlsResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(label: str, host: str) -> TlsResult:
        async with semaphore:
            return await measure_tls(
                label, host, port=port, timeout=timeout, source_ip=source_ip, verify=verify, pins=pins
            )

    return list(await asyncio.gather(*(_bounded(label, host) for label, host in targets)))
