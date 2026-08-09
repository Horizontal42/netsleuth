from __future__ import annotations

import asyncio
import concurrent.futures
import json
import platform
import shutil
import threading
from typing import Awaitable, Callable, TypeVar

from netsleuth.models import Capabilities, TraceHop, TraceResult
from netsleuth.probes.icmp_win import IcmpReply, classify_status
from netsleuth.traceparse import build_trace_result, finalize_hop

_T = TypeVar("_T")


def _run_in_daemon_thread(func: Callable[..., _T], *args: object) -> "asyncio.Future[_T]":
    # asyncio.to_thread()/loop.run_in_executor(None, ...) queue work onto the
    # ThreadPoolExecutor-backed default executor, whose worker threads are non-daemon
    # and get joined by concurrent.futures' atexit handler. If the underlying call
    # (a blocking WinAPI IcmpSendEcho2) ever outlives its own timeout budget, that
    # join blocks process exit indefinitely. A raw daemon thread is never tracked
    # by that handler, so it can never hold the process open.
    result: concurrent.futures.Future = concurrent.futures.Future()

    def _target() -> None:
        if not result.set_running_or_notify_cancel():
            return
        try:
            value = func(*args)
        except BaseException as exc:  # noqa: BLE001 - propagated to the awaiting coroutine
            result.set_exception(exc)
        else:
            result.set_result(value)

    threading.Thread(target=_target, name="netsleuth-icmp-win", daemon=True).start()
    return asyncio.wrap_future(result)


def tier_order(caps: Capabilities, tcp_trace: bool = False) -> list[str]:
    # An explicit --tcp-trace means the user already knows ICMP is being filtered,
    # so it leads rather than sits behind tiers that are about to fail.
    order: list[str] = ["tcp_trace"] if tcp_trace else []
    if caps.mtr_binary:
        order.append("mtr_json")
    if caps.icmp_win_api:
        order.append("icmp_win")
    elif caps.icmp_dgram or caps.icmp_raw:
        order.append("icmplib")
    if caps.traceroute_binary:
        order.append("system_traceroute")
    return order


def filter_trace_tiers(order: list[str], os_name: str, forced_v4: bool) -> tuple[list[str], list[str]]:
    # Windows tracert exposes a source-address override for IPv6 only (-S), never
    # for IPv4, so it cannot honor a forced IPv4 bind; running it anyway would
    # silently measure the OS-default path under a report claiming otherwise.
    if not forced_v4 or os_name != "Windows" or "system_traceroute" not in order:
        return order, []
    return [t for t in order if t != "system_traceroute"], ["system_traceroute"]


def trace_argv(
    backend: str,
    binary: str,
    target: str,
    max_hops: int,
    cycles: int,
    os_name: str,
    source_ip: str | None = None,
) -> list[str]:
    if backend == "mtr_json":
        args = [binary, "--json", "--report-cycles", str(cycles), "--max-ttl", str(max_hops)]
        if source_ip:
            args += ["--address", source_ip]
        args.append(target)
        return args
    if backend == "system_traceroute":
        if os_name == "Windows":
            return [binary, "-h", str(max_hops), "-w", "2", target]
        args = [binary, "-m", str(max_hops), "-w", "2"]
        if source_ip:
            args += ["-s", source_ip]
        args.append(target)
        return args
    raise ValueError(f"unsupported backend for trace_argv: {backend!r}")


async def run_cascade(tiers: list[tuple[str, Callable[[], Awaitable[TraceResult]]]]) -> TraceResult:
    for _name, tier in tiers:
        try:
            result = await tier()
        except asyncio.CancelledError:
            raise
        except BaseException:  # noqa: BLE001 - a dead tier is data, the next tier gets its turn
            continue
        if result.hops:
            return result
    return TraceResult(backend="none", hops=[], completed=False)


def hops_from_win_replies(replies: list[tuple[int, IcmpReply]]) -> list[TraceHop]:
    hops: list[TraceHop] = []
    for ttl, reply in replies:
        kind = classify_status(reply.status)
        rtt = reply.rtt_ms if kind in ("ok", "ttl_expired") else None
        hops.append(finalize_hop(TraceHop(ttl=ttl, ip=reply.address, probes=[rtt])))
    return hops


async def _run(args: list[str], timeout: float) -> str:
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise
    return stdout.decode(_console_encoding(), errors="replace")


def _console_encoding() -> str:
    # Windows console tools emit the OEM code page (cp866 on Russian Windows),
    # which is why every parser here works on decoded text and never on bytes.
    if platform.system() != "Windows":
        return "utf-8"
    import ctypes

    try:
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        return "utf-8"


async def _tier_mtr(
    target: str, binary: str, cycles: int, max_hops: int, timeout: float, source_ip: str | None = None
) -> TraceResult:
    text = await _run(
        trace_argv("mtr_json", binary, target, max_hops, cycles, platform.system(), source_ip), timeout
    )
    payload = json.loads(text)
    report = payload.get("report") or {}
    hops = []
    for entry in report.get("hubs") or []:
        hop = TraceHop(
            ttl=entry.get("count", 0),
            ip=None if entry.get("host") in ("???", None) else entry.get("host"),
            probes=[],
            loss_pct=float(entry.get("Loss%", 0.0)),
            min_ms=entry.get("Best"),
            avg_ms=entry.get("Avg"),
            max_ms=entry.get("Wrst"),
            jitter_ms=entry.get("StDev"),
        )
        hops.append(hop)
    return TraceResult(
        target=target,
        backend="mtr_json",
        hops=hops,
        cycles=cycles,
        completed=bool(hops) and hops[-1].ip is not None,
    )


async def _tier_icmp_win(
    target: str, max_hops: int, timeout: float, source_ip: str | None = None
) -> TraceResult:
    from netsleuth.probes.icmp_win import trace_hops_win

    replies = await _run_in_daemon_thread(trace_hops_win, target, max_hops, int(timeout * 1000), source_ip)
    hops = hops_from_win_replies(replies)
    return TraceResult(
        target=target,
        backend="icmp_win",
        hops=hops,
        cycles=1,
        completed=bool(hops) and classify_status(replies[-1][1].status) == "ok",
        max_hops_reached=bool(hops) and hops[-1].ttl >= max_hops,
    )


async def _tier_icmplib(
    target: str, max_hops: int, timeout: float, source_ip: str | None = None
) -> TraceResult:
    # icmplib has no async traceroute (only async_ping) and traceroute() always
    # needs a raw socket -- there is no unprivileged/"privileged=" variant for it,
    # unlike ping. Run the sync call off the event loop thread.
    from icmplib import traceroute as icmplib_traceroute

    raw = await asyncio.to_thread(
        icmplib_traceroute, target, max_hops=max_hops, timeout=timeout, source=source_ip
    )
    hops = [
        finalize_hop(TraceHop(ttl=h.distance, ip=h.address, probes=list(h.rtts)))
        for h in raw
    ]
    return TraceResult(
        target=target,
        backend="icmplib",
        hops=hops,
        cycles=1,
        completed=bool(hops) and hops[-1].ip is not None,
        max_hops_reached=bool(hops) and hops[-1].ttl >= max_hops,
    )


async def _tier_system(
    target: str, binary: str, max_hops: int, timeout: float, source_ip: str | None = None
) -> TraceResult:
    os_name = platform.system()
    args = trace_argv("system_traceroute", binary, target, max_hops, 1, os_name, source_ip)
    text = await _run(args, timeout)
    return build_trace_result(text, os_name, target=target, resolved_ip=None, max_hops=max_hops)


async def _tier_tcp_trace(
    target: str, max_hops: int, timeout: float, port: int = 443, source_ip: str | None = None
) -> TraceResult:
    # scapy ships in the optional `tcptrace` extra and needs Npcap (Windows) or
    # root (Unix); an ImportError here just falls through to the next tier.
    from scapy.layers.inet import IP, TCP
    from scapy.sendrecv import sr

    def _probe() -> list[TraceHop]:
        packet = IP(dst=target, ttl=(1, max_hops))
        if source_ip:
            packet.src = source_ip
        answered, _unanswered = sr(
            packet / TCP(dport=port, flags="S"),
            timeout=timeout,
            verbose=0,
        )
        hops = [
            finalize_hop(
                TraceHop(ttl=sent.ttl, ip=received.src, probes=[(received.time - sent.sent_time) * 1000.0])
            )
            for sent, received in answered
        ]
        return sorted(hops, key=lambda hop: hop.ttl)

    hops = await asyncio.to_thread(_probe)
    return TraceResult(
        target=target,
        backend="tcp_trace",
        hops=hops,
        cycles=1,
        completed=bool(hops) and hops[-1].ip == target,
        max_hops_reached=bool(hops) and hops[-1].ttl >= max_hops,
    )


async def traceroute(
    target: str,
    caps: Capabilities,
    max_hops: int,
    cycles: int,
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
    tcp_trace: bool = False,
    source_ip: str | None = None,
) -> TraceResult:
    builders = {
        "tcp_trace": lambda: _tier_tcp_trace(target, max_hops, timeout, source_ip=source_ip),
        "mtr_json": lambda: _tier_mtr(
            target, caps.mtr_binary or shutil.which("mtr") or "mtr", cycles, max_hops, timeout, source_ip
        ),
        "icmp_win": lambda: _tier_icmp_win(target, max_hops, timeout, source_ip),
        "icmplib": lambda: _tier_icmplib(target, max_hops, timeout, source_ip=source_ip),
        "system_traceroute": lambda: _tier_system(
            target, caps.traceroute_binary or "traceroute", max_hops, timeout, source_ip
        ),
    }
    order = tier_order(caps, tcp_trace)
    order, _dropped = filter_trace_tiers(order, caps.os_name, forced_v4=bool(source_ip))
    tiers = [(name, builders[name]) for name in order]
    if semaphore is None:
        return await run_cascade(tiers)
    async with semaphore:
        return await run_cascade(tiers)
