from __future__ import annotations

import re
from urllib.parse import parse_qs

from netcheck.models import CfL4Stats
from netcheck.stats import percentile

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
