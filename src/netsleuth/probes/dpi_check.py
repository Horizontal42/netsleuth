from __future__ import annotations

import asyncio
import time

from netsleuth.models import DpiCheckResult, PortProbe


def classify_connect_outcome(exc: BaseException | None) -> str:
    if exc is None:
        return "open"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "filtered"
    return "error"


def dpi_verdict(ports: list[PortProbe]) -> tuple[str, str, str]:
    states = [p.state for p in ports]

    if not states or all(s == "filtered" for s in states):
        rationale = (
            "All probed ports were silently dropped (or the list of ports was empty). "
            "This could mean the server is offline, or that a middlebox is filtering "
            "traffic to it — the two are indistinguishable from the client side, so no "
            "DPI verdict can be asserted."
        )
        rationale_ru = (
            "Все проверенные порты не ответили (пакеты тихо потерялись), или список "
            "портов был пуст. Это может означать, что сервер выключен, или что "
            "провайдер/middlebox фильтрует трафик к нему — со стороны клиента отличить "
            "одно от другого нельзя, поэтому уверенный вывод о DPI сделать нельзя."
        )
        return "unreachable", rationale, rationale_ru

    has_open = "open" in states
    has_reset = "reset" in states
    has_filtered = "filtered" in states

    if has_reset and has_open:
        rationale = (
            "At least one port responded normally (open) while another had its "
            "connection actively reset. Active RST injection alongside working ports "
            "is a characteristic signature of DPI-based interference."
        )
        rationale_ru = (
            "Хотя бы один порт ответил нормально (открыт), а на другом соединение было "
            "принудительно сброшено (RST). Активная инъекция RST на фоне работающих "
            "портов — характерный признак вмешательства DPI."
        )
        return "reset_injection", rationale, rationale_ru

    if has_open and has_filtered:
        rationale = (
            "Some ports responded (open) while others were silently dropped (filtered). "
            "This mixed pattern suggests selective filtering of specific ports/services "
            "rather than a fully offline host."
        )
        rationale_ru = (
            "Часть портов ответила (открыты), а часть тихо не ответила (отфильтрованы). "
            "Такая смешанная картина указывает на выборочную фильтрацию отдельных "
            "портов/сервисов, а не на полностью выключенный хост."
        )
        return "partial_filtering", rationale, rationale_ru

    rationale = (
        "Every probed port returned a clean, honest TCP outcome (open or refused) with "
        "no silent drops or connection resets observed."
    )
    rationale_ru = (
        "Все проверенные порты дали честный TCP-ответ (открыт или отказ), без тихих "
        "потерь пакетов или сбросов соединения."
    )
    return "clean", rationale, rationale_ru


async def probe_port(
    ip: str, port: int, *, timeout: float, source_ip: str | None = None
) -> PortProbe:
    local_addr = (source_ip, 0) if source_ip else None
    began = time.perf_counter()
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, local_addr=local_addr), timeout=timeout
        )
        rtt_ms = (time.perf_counter() - began) * 1000.0
        return PortProbe(port=port, state="open", rtt_ms=rtt_ms)
    except asyncio.CancelledError:
        raise
    except BaseException as exc:  # noqa: BLE001 - a failed probe is a value here, not control flow
        state = classify_connect_outcome(exc)
        detail = str(exc) or exc.__class__.__name__
        return PortProbe(port=port, state=state, detail=detail)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def check_dpi(
    target: str,
    resolved_ip: str,
    ports: list[int],
    *,
    timeout: float,
    delay: float,
    concurrency: int,
    source_ip: str | None = None,
) -> DpiCheckResult:
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(port: int) -> PortProbe:
        async with semaphore:
            return await probe_port(resolved_ip, port, timeout=timeout, source_ip=source_ip)

    tasks = []
    for index, port in enumerate(ports):
        if index:
            await asyncio.sleep(delay)
        tasks.append(asyncio.ensure_future(_bounded(port)))

    probes = list(await asyncio.gather(*tasks)) if tasks else []

    verdict, rationale, rationale_ru = dpi_verdict(probes)
    return DpiCheckResult(
        target=target,
        resolved_ip=resolved_ip,
        consented=True,
        ports=probes,
        verdict=verdict,
        rationale=rationale,
        rationale_ru=rationale_ru,
    )
