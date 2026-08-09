from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.live import Live
from rich.table import Table

from netsleuth import __version__
from netsleuth.config import Settings
from netsleuth.exporter import atomic_write, compact_timestamp, dump_json, sanitize_name, sparkline
from netsleuth.ip_geo import gather_identity
from netsleuth.models import PingResult, SpeedResult, to_jsonable
from netsleuth.netinfo import detect_capabilities
from netsleuth.orchestration import run_module, utc_now_iso
from netsleuth.probes.latency import ping_fanout

WATCH_SCHEMA_VERSION = 1


def is_speedtest_cycle(cycle: int, every_n: int) -> bool:
    # Cycle 1 measures speed so the session opens with a baseline to compare against.
    if every_n <= 0 or cycle < 1:
        return False
    return (cycle - 1) % every_n == 0


def next_delay(cycle_started: float, now: float, interval: float) -> float:
    # Subtracting the work already done keeps the cycle cadence from drifting
    # further behind on every tick.
    return max(0.0, interval - (now - cycle_started))


def summarize_cycle(
    cycle: int,
    at: str,
    pings: list[PingResult],
    speed: SpeedResult | None,
) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "at": at,
        "hosts": {
            p.label: {
                "host": p.host,
                "method": p.method,
                "avg_ms": p.avg_ms,
                "jitter_ms": p.jitter_ms,
                "loss_pct": p.loss_pct,
            }
            for p in pings
        },
        "speed": None
        if speed is None
        else {
            "method": speed.method,
            "download_mbps": speed.download_mbps,
            "upload_mbps": speed.upload_mbps,
            "bufferbloat_grade": speed.bufferbloat_grade,
        },
    }


@dataclass
class WatchSession:
    started_at: str
    asn: str | None = None
    interval_seconds: int = 60
    speedtest_every_n_cycles: int = 10
    cycles: list[dict] = field(default_factory=list)

    def add(self, summary: dict) -> None:
        self.cycles.append(summary)

    def history(self, label: str) -> list[float | None]:
        return [(cycle["hosts"].get(label) or {}).get("avg_ms") for cycle in self.cycles]

    def labels(self) -> list[str]:
        seen: list[str] = []
        for cycle in self.cycles:
            for label in cycle["hosts"]:
                if label not in seen:
                    seen.append(label)
        return seen

    def filename(self) -> str:
        return f"watch_{sanitize_name(self.asn)}_{compact_timestamp(self.started_at)}.json"

    def to_report(self) -> dict[str, Any]:
        return {
            "schema_version": WATCH_SCHEMA_VERSION,
            "kind": "watch",
            "meta": {
                "started_at": self.started_at,
                "finished_at": utc_now_iso(),
                "asn": self.asn,
                "interval_seconds": self.interval_seconds,
                "speedtest_every_n_cycles": self.speedtest_every_n_cycles,
                "cycle_count": len(self.cycles),
            },
            "cycles": to_jsonable(self.cycles),
        }


def write_session(session: WatchSession, logs_dir: Path) -> Path:
    return atomic_write(Path(logs_dir) / session.filename(), dump_json(session.to_report()))


def render_dashboard(session: WatchSession) -> Table:
    table = Table(title=f"netsleuth --watch · {session.asn or 'unknown ASN'} · cycle {len(session.cycles)}")
    for column in ("Host", "Avg ms", "Jitter", "Loss", "Trend"):
        table.add_column(column)
    latest = session.cycles[-1]["hosts"] if session.cycles else {}
    for label in session.labels():
        row = latest.get(label) or {}
        table.add_row(
            label,
            "—" if row.get("avg_ms") is None else f"{row['avg_ms']:g}",
            "—" if row.get("jitter_ms") is None else f"{row['jitter_ms']:g}",
            f"{row.get('loss_pct', 0)}%",
            sparkline(session.history(label)[-40:]),
        )
    speed = next((c["speed"] for c in reversed(session.cycles) if c["speed"]), None)
    if speed:
        table.caption = (
            f"last speedtest: {speed['download_mbps']} / {speed['upload_mbps']} Mbps "
            f"via {speed['method']} · bufferbloat {speed['bufferbloat_grade']}"
        )
    return table


async def run_watch(settings: Settings, options) -> Path:
    # Imported here, not at module import time: cli imports watch lazily for --watch,
    # and a module-level import back into cli would close the cycle.
    from netsleuth.cli import _speed_section

    caps = detect_capabilities()
    session = WatchSession(
        started_at=utc_now_iso(),
        interval_seconds=settings.watch.interval_seconds,
        speedtest_every_n_cycles=settings.watch.speedtest_every_n_cycles,
    )
    hosts = [(h.label, h.host) for h in settings.probing.reference_hosts]
    if options.extra_host:
        hosts.append(("target-host", options.extra_host))
    console = Console()
    console.print(f"netsleuth {__version__} · watching every {session.interval_seconds}s · Ctrl-C to stop")

    async with httpx.AsyncClient(
        timeout=settings.timeouts.http_seconds,
        follow_redirects=True,
        headers={"User-Agent": f"netsleuth/{__version__}"},
    ) as client:
        try:
            geo, _cf, _flags, _raw = await gather_identity(client, settings.providers)
            session.asn = geo.asn
        except (httpx.HTTPError, OSError):
            session.asn = None

        cycle = 1
        try:
            with Live(render_dashboard(session), console=console, refresh_per_second=settings.watch.dashboard_refresh_hz) as live:
                while True:
                    began = time.perf_counter()
                    pings = await ping_fanout(
                        hosts,
                        caps,
                        settings.probing.quick_ping_count,
                        settings.probing.ping_interval_seconds,
                        settings.probing.ping_timeout_seconds,
                    )
                    speed = None
                    if is_speedtest_cycle(cycle, session.speedtest_every_n_cycles) and not options.quick:
                        result = await run_module(
                            "speed",
                            _speed_section(client, settings, options, None),
                            timeout=settings.timeouts.speedtest_seconds,
                        )
                        speed = result.data if result.status == "ok" else None
                    session.add(summarize_cycle(cycle, utc_now_iso(), pings, speed))
                    live.update(render_dashboard(session))
                    await asyncio.sleep(next_delay(began, time.perf_counter(), session.interval_seconds))
                    cycle += 1
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass

    path = write_session(session, Path(settings.output.logs_dir))
    console.print(f"Watch session written to {path}")
    return path
