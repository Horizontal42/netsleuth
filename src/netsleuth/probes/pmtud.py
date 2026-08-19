from __future__ import annotations

import asyncio
import platform
import shutil
import socket

from netsleuth.models import PmtuResult

_IPV4_ICMP_OVERHEAD = 28  # 20-byte IPv4 header + 8-byte ICMP header
_STANDARD_MTU = 1500
_FRAG_NEEDED_MARKERS = ("frag", "too long")


def next_probe_size(low: int, high: int) -> int:
    return (low + high) // 2


def mtu_from_search(low: int, high: int, overhead: int = _IPV4_ICMP_OVERHEAD) -> int:
    return low + overhead


def classify_pmtu(
    discovered: int | None, iface_mtu: int | None, saw_frag_needed: bool
) -> tuple[str, str, str]:
    floor = iface_mtu or _STANDARD_MTU
    if discovered is None:
        return "unknown", "path MTU could not be determined", "не удалось определить MTU пути"
    if discovered >= floor:
        return (
            "ok",
            f"the path supports the full {discovered}-byte MTU",
            f"путь поддерживает полный MTU {discovered} байт",
        )
    if saw_frag_needed:
        return (
            "reduced",
            f"path MTU is {discovered} bytes; the path correctly signals fragmentation needed",
            f"MTU пути — {discovered} байт; путь корректно сигнализирует о необходимости фрагментации",
        )
    return (
        "blackhole",
        f"packets above {discovered} bytes vanish with no ICMP reply -- PMTUD appears blocked",
        f"пакеты крупнее {discovered} байт исчезают без ответа ICMP -- похоже, PMTUD заблокирован",
    )


def unix_ping_df_argv(binary: str, host: str, payload_size: int, timeout: float, os_name: str) -> list[str]:
    timeout_s = max(1, int(timeout + 0.999))
    if os_name == "Darwin":
        return [binary, "-D", "-s", str(payload_size), "-c", "1", "-t", str(timeout_s), host]
    return [binary, "-M", "do", "-s", str(payload_size), "-c", "1", "-W", str(timeout_s), host]


def supports_df() -> tuple[bool, str]:
    system = platform.system()
    if system == "Windows":
        from netsleuth.probes.icmp_win import win_icmp_available

        if win_icmp_available():
            return True, "icmp_win"
        return False, "Windows ICMP API unavailable"
    binary = shutil.which("ping")
    if not binary:
        return False, "no ping binary found"
    return True, binary


async def _probe_windows(
    resolved_ip: str, size: int, timeout: float, source_ip: str | None
) -> tuple[bool, bool]:
    from netsleuth.probes.icmp_win import classify_status, echo_once

    payload = b"\x00" * max(0, size - _IPV4_ICMP_OVERHEAD)
    timeout_ms = int(timeout * 1000)

    def _run():
        return echo_once(resolved_ip, ttl=64, timeout_ms=timeout_ms, payload=payload, source_ip=source_ip, df=True)

    reply = await asyncio.to_thread(_run)
    kind = classify_status(reply.status)
    return kind == "ok", kind == "packet_too_big"


async def _probe_unix(binary: str, host: str, size: int, timeout: float, os_name: str) -> tuple[bool, bool]:
    payload_size = max(0, size - _IPV4_ICMP_OVERHEAD)
    args = unix_ping_df_argv(binary, host, payload_size, timeout, os_name)
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout + 2.0)
    except TimeoutError:
        process.kill()
        return False, False
    if process.returncode == 0:
        return True, False
    text = stdout.decode("utf-8", "replace").lower()
    return False, any(marker in text for marker in _FRAG_NEEDED_MARKERS)


async def probe_pmtu(
    host: str,
    *,
    low: int = 576,
    high: int = 1500,
    timeout: float = 2.0,
    iface_mtu: int | None = None,
    source_ip: str | None = None,
) -> PmtuResult:
    result = PmtuResult(host=host, iface_mtu=iface_mtu)
    available, detail = supports_df()
    if not available:
        result.note = f"PMTUD probe unavailable: {detail}"
        result.note_ru = f"Проба PMTUD недоступна: {detail}"
        return result

    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        resolved_ip = infos[0][4][0]
    except (OSError, IndexError) as exc:
        result.note = f"could not resolve {host}: {exc}"
        result.note_ru = f"не удалось разрешить {host}: {exc}"
        return result
    result.resolved_ip = resolved_ip

    system = platform.system()
    result.method = "icmp_win" if system == "Windows" else "system_ping"

    async def _probe(size: int) -> tuple[bool, bool]:
        if system == "Windows":
            return await _probe_windows(resolved_ip, size, timeout, source_ip)
        return await _probe_unix(detail, host, size, timeout, system)

    probes: list[tuple[int, bool]] = []
    saw_frag_needed = False

    ok, frag = await _probe(low)
    probes.append((low, ok))
    saw_frag_needed = saw_frag_needed or frag
    if not ok:
        result.probes = probes
        result.note = f"even the {low}-byte floor failed; cannot determine the path MTU"
        result.note_ru = f"даже минимальный размер {low} байт не прошёл; определить MTU пути не удалось"
        return result

    working_low, failing_high = low, high + 1
    while failing_high - working_low > 1:
        size = next_probe_size(working_low, failing_high)
        ok, frag = await _probe(size)
        probes.append((size, ok))
        saw_frag_needed = saw_frag_needed or frag
        if ok:
            working_low = size
        else:
            failing_high = size

    result.probes = probes
    result.discovered_mtu = working_low
    result.verdict, result.note, result.note_ru = classify_pmtu(working_low, iface_mtu, saw_frag_needed)
    return result
