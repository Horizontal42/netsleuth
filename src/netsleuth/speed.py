from __future__ import annotations

import re
from urllib.parse import parse_qs

from netsleuth.models import CfL4Stats
from netsleuth.stats import percentile

_CFL4_RE = re.compile(r'cfL4\s*;\s*desc\s*=\s*"?\??(?P<query>[^",]*)"?')


def mbps(bytes_transferred: int, seconds: float) -> float:
    if seconds <= 0 or bytes_transferred <= 0:
        return 0.0
    return (bytes_transferred * 8) / seconds / 1_000_000


def throughput_from_samples(samples: list[tuple[int, float]], p: float = 90.0) -> float:
    rates = [mbps(size, duration) for size, duration in samples]
    rates = [rate for rate in rates if rate > 0]
    if not rates:
        return 0.0
    return round(percentile(rates, p), 3)


def _as_int(value: str | None) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _us_to_ms(value: str | None) -> float | None:
    number = _as_int(value)
    return None if number is None else round(number / 1000.0, 3)


def parse_server_timing_cfl4(header: str) -> CfL4Stats | None:
    match = _CFL4_RE.search(header or "")
    if not match:
        return None
    fields = {k: v[0] for k, v in parse_qs(match.group("query"), keep_blank_values=True).items()}
    return CfL4Stats(
        rtt_ms=_us_to_ms(fields.get("rtt")),
        min_rtt_ms=_us_to_ms(fields.get("min_rtt")),
        rtt_var_ms=_us_to_ms(fields.get("rtt_var")),
        delivery_rate_bps=_as_int(fields.get("delivery_rate")),
        cwnd=_as_int(fields.get("cwnd")),
        unsent_bytes=_as_int(fields.get("unsent_bytes")),
        recv_bytes=_as_int(fields.get("recv_bytes")),
    )


def bufferbloat_delta(idle_rtt_ms: float | None, loaded_rtts_ms: list[float]) -> float | None:
    if idle_rtt_ms is None or not loaded_rtts_ms:
        return None
    loaded = percentile(sorted(loaded_rtts_ms), 95.0)
    return round(max(0.0, loaded - idle_rtt_ms), 3)


import asyncio
import time
from collections.abc import Awaitable, Callable

from netsleuth.models import SpeedResult, TierAttempt

NDT7_CONSENT_NOTICE = (
    "M-Lab NDT7 publishes every measurement as public CC0 open data, including your "
    "IP address. Pass --ndt7 only if that is acceptable to you."
)


async def run_speed_cascade(
    tiers: list[tuple[str, Callable[[], Awaitable[SpeedResult]]]],
) -> SpeedResult:
    attempts: list[TierAttempt] = []
    for name, tier in tiers:
        began = time.perf_counter()
        try:
            result = await tier()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - a dead tier is data, not control flow
            attempts.append(
                TierAttempt(
                    tier=name,
                    ok=False,
                    reason=str(exc) or exc.__class__.__name__,
                    duration_ms=int((time.perf_counter() - began) * 1000),
                )
            )
            continue
        duration_ms = int((time.perf_counter() - began) * 1000)
        if not result.download_mbps:
            attempts.append(
                TierAttempt(tier=name, ok=False, reason="no throughput measured", duration_ms=duration_ms)
            )
            continue
        attempts.append(TierAttempt(tier=name, ok=True, reason=None, duration_ms=duration_ms))
        result.tier_attempts = attempts
        return result
    return SpeedResult(method="none", tier_attempts=attempts)


import json

import httpx

from netsleuth.config import Speedtest


def ookla_interface_args(iface_name: str | None, ipv4: str | None) -> list[str]:
    if iface_name:
        return ["--interface", iface_name]
    if ipv4:
        return ["--ip", ipv4]
    return []


async def tier_ookla(
    binary: str,
    server: str | None,
    timeout: float,
    iface_name: str | None = None,
    ipv4: str | None = None,
) -> SpeedResult:
    args = [binary, "--format=json", "--accept-license", "--accept-gdpr"]
    args += ookla_interface_args(iface_name, ipv4)
    if server:
        args += ["--server-id", server] if server.isdigit() else ["--host", server]
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    payload = json.loads(stdout.decode("utf-8", "replace"))
    download = payload.get("download") or {}
    upload = payload.get("upload") or {}
    server_info = payload.get("server") or {}
    return SpeedResult(
        method="ookla_bin",
        download_mbps=round(mbps(download.get("bytes", 0), (download.get("elapsed", 0) or 0) / 1000), 3),
        upload_mbps=round(mbps(upload.get("bytes", 0), (upload.get("elapsed", 0) or 0) / 1000), 3),
        server=f"{server_info.get('name', '')} ({server_info.get('location', '')})".strip(),
        idle_rtt_ms=(payload.get("ping") or {}).get("latency"),
        server_country=server_info.get("country") or None,
    )


async def tier_cloudflare(client: httpx.AsyncClient, cfg: Speedtest, timeout: float) -> SpeedResult:
    down_samples: list[tuple[int, float]] = []
    cfl4: CfL4Stats | None = None
    for size in cfg.download_sizes_bytes:
        began = time.perf_counter()
        response = await client.get(
            f"{cfg.cloudflare_base_url}/__down", params={"bytes": size}, timeout=timeout
        )
        response.raise_for_status()
        down_samples.append((len(response.content), time.perf_counter() - began))
        cfl4 = parse_server_timing_cfl4(response.headers.get("server-timing", "")) or cfl4
    up_samples: list[tuple[int, float]] = []
    for size in cfg.upload_sizes_bytes:
        payload = b"\x00" * size
        began = time.perf_counter()
        response = await client.post(f"{cfg.cloudflare_base_url}/__up", content=payload, timeout=timeout)
        response.raise_for_status()
        up_samples.append((size, time.perf_counter() - began))
    return SpeedResult(
        method="cloudflare",
        download_mbps=throughput_from_samples(down_samples),
        upload_mbps=throughput_from_samples(up_samples),
        server="speed.cloudflare.com",
        cfL4_stats=cfl4,
    )


async def tier_fastcom(client: httpx.AsyncClient, cfg: Speedtest, timeout: float) -> SpeedResult:
    response = await client.get(
        cfg.fastcom_api_url,
        params={"https": "true", "token": "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm", "urlCount": "3"},
        timeout=timeout,
    )
    response.raise_for_status()
    targets = response.json().get("targets") or []
    samples: list[tuple[int, float]] = []
    on_net: bool | None = None
    for target in targets:
        url = target.get("url")
        if not url:
            continue
        location = (target.get("location") or {}).get("country")
        on_net = on_net or bool(location)
        began = time.perf_counter()
        body = await client.get(url, timeout=timeout)
        body.raise_for_status()
        samples.append((len(body.content), time.perf_counter() - began))
    return SpeedResult(
        method="fastcom",
        download_mbps=throughput_from_samples(samples),
        upload_mbps=None,
        server=targets[0].get("url").split("/")[2] if targets and targets[0].get("url") else None,
        netflix_oca_onnet=on_net,
        server_country=(targets[0].get("location") or {}).get("country") if targets else None,
    )


async def tier_ndt7(
    client: httpx.AsyncClient, cfg: Speedtest, timeout: float, source_ip: str | None = None
) -> SpeedResult:
    import websockets

    locate = await client.get(cfg.ndt7_locate_url, timeout=timeout)
    locate.raise_for_status()
    results = locate.json().get("results") or []
    if not results:
        raise RuntimeError("no ndt7 server offered by locate.measurementlab.net")
    url = results[0]["urls"]["wss:///ndt/v7/download"]
    total = 0
    connect_kwargs = {"local_addr": (source_ip, 0)} if source_ip else {}
    began = time.perf_counter()
    async with websockets.connect(
        url, subprotocols=["net.measurementlab.ndt.v7"], **connect_kwargs
    ) as socket:
        while time.perf_counter() - began < 10:
            try:
                message = await asyncio.wait_for(socket.recv(), timeout=timeout)
            except (TimeoutError, Exception):
                break
            total += len(message) if isinstance(message, (bytes, bytearray)) else len(message.encode())
    elapsed = time.perf_counter() - began
    return SpeedResult(
        method="ndt7",
        download_mbps=round(mbps(total, elapsed), 3),
        upload_mbps=None,
        server=results[0].get("machine"),
        server_country=(results[0].get("location") or {}).get("country") or None,
    )


from netsleuth.config import BufferbloatBands
from netsleuth.interpret import grade_bufferbloat
from netsleuth.stats import rtt_stats


async def probe_while(
    coro: Awaitable[None],
    probe: Callable[[], Awaitable[float | None]],
    interval: float,
) -> list[float]:
    samples: list[float] = []
    task = asyncio.ensure_future(coro)
    while not task.done():
        sample = await probe()
        if sample is not None:
            samples.append(sample)
        await asyncio.sleep(interval)
    await task
    return samples


async def measure_with_bufferbloat(
    result: SpeedResult,
    idle_rtt_ms: float | None,
    bands: BufferbloatBands,
    run_download: Callable[[], Awaitable[None]],
    run_upload: Callable[[], Awaitable[None]],
    probe: Callable[[], Awaitable[float | None]],
    interval: float,
) -> SpeedResult:
    # This is the one place a measurement is allowed to overlap another: the
    # whole point is to see what latency does while the link is saturated.
    down_samples = await probe_while(run_download(), probe, interval)
    up_samples = await probe_while(run_upload(), probe, interval)
    result.idle_rtt_ms = idle_rtt_ms
    result.loaded_rtt_down_ms = rtt_stats(list(down_samples)).avg_ms
    result.loaded_rtt_up_ms = rtt_stats(list(up_samples)).avg_ms
    result.bufferbloat_down_ms = bufferbloat_delta(idle_rtt_ms, down_samples)
    result.bufferbloat_up_ms = bufferbloat_delta(idle_rtt_ms, up_samples)
    worst_delta = max(
        [d for d in (result.bufferbloat_down_ms, result.bufferbloat_up_ms) if d is not None],
        default=None,
    )
    result.bufferbloat_grade = grade_bufferbloat(worst_delta, bands)
    return result
