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
from netsleuth.alerting import build_payload, post_webhook, should_fire
from netsleuth.config import Settings, Thresholds
from netsleuth.exporter import atomic_write, dump_json, readable_timestamp, report_date_dir, sanitize_name, sparkline
from netsleuth.interpret import latency_findings, overall_verdict, speed_findings
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
    thresholds: Thresholds | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or Thresholds()
    findings = latency_findings(pings, thresholds) + (
        speed_findings(speed, thresholds.bufferbloat_ms) if speed is not None else []
    )
    status, score, _summary = overall_verdict(findings)
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
        "status": status,
        "score": score,
        "finding_ids": [f.id for f in findings],
    }


@dataclass
class WatchSession:
    started_at: str
    asn: str | None = None
    interval_seconds: int = 60
    speedtest_every_n_cycles: int = 10
    interface: str | None = None
    bind_ipv4: str | None = None
    cycles: list[dict] = field(default_factory=list)
    alerts_fired: int = 0

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
        return f"watch_{sanitize_name(self.asn)}_{readable_timestamp(self.started_at)}.json"

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
                "interface": self.interface,
                "bind_ipv4": self.bind_ipv4,
                "alerts_fired": self.alerts_fired,
            },
            "cycles": to_jsonable(self.cycles),
        }


def write_session(session: WatchSession, logs_dir: Path) -> Path:
    base = Path(logs_dir) / report_date_dir(session.started_at)
    return atomic_write(base / session.filename(), dump_json(session.to_report()))


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
    caption_parts: list[str] = []
    if session.cycles:
        last = session.cycles[-1]
        caption_parts.append(f"verdict: {last.get('status', '?')} ({last.get('score', '?')}/100)")
    speed = next((c["speed"] for c in reversed(session.cycles) if c["speed"]), None)
    if speed:
        caption_parts.append(
            f"last speedtest: {speed['download_mbps']} / {speed['upload_mbps']} Mbps "
            f"via {speed['method']} · bufferbloat {speed['bufferbloat_grade']}"
        )
    if caption_parts:
        table.caption = " · ".join(caption_parts)
    return table


async def run_watch(settings: Settings, options) -> Path:
    # Imported here, not at module import time: cli imports watch lazily for --watch,
    # and a module-level import back into cli would close the cycle.
    from netsleuth.cli import _speed_section

    caps = detect_capabilities()
    bind = options.bind
    session = WatchSession(
        started_at=utc_now_iso(),
        interval_seconds=settings.watch.interval_seconds,
        speedtest_every_n_cycles=settings.watch.speedtest_every_n_cycles,
        interface=bind.iface_name if bind else None,
        bind_ipv4=bind.ipv4 if bind else None,
    )
    hosts = [(h.label, h.host) for h in settings.probing.reference_hosts]
    if options.extra_host:
        hosts.append(("target-host", options.extra_host))
    console = Console()
    console.print(f"netsleuth {__version__} · watching every {session.interval_seconds}s · Ctrl-C to stop")

    webhook_url = options.webhook or settings.watch.webhook_url
    fire_on = set(settings.watch.webhook_on)
    if webhook_url:
        console.print(
            f"[yellow]--watch will POST your ASN and finding titles to {webhook_url} "
            f"on a verdict transition into {sorted(fire_on)}.[/yellow]"
        )
    previous_status: str | None = None
    last_fired_at: float | None = None

    transport = httpx.AsyncHTTPTransport(local_address=bind.ipv4) if bind else None
    async with httpx.AsyncClient(
        transport=transport,
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
                        source_ip=bind.ipv4 if bind else None,
                    )
                    speed = None
                    if is_speedtest_cycle(cycle, session.speedtest_every_n_cycles) and not options.quick:
                        result = await run_module(
                            "speed",
                            _speed_section(client, settings, options, None),
                            timeout=settings.timeouts.speedtest_seconds,
                        )
                        speed = result.data if result.status == "ok" else None
                    cycle_summary = summarize_cycle(cycle, utc_now_iso(), pings, speed, settings.thresholds)
                    session.add(cycle_summary)
                    current_status = cycle_summary["status"]
                    if webhook_url and should_fire(
                        previous_status,
                        current_status,
                        last_fired_at,
                        time.perf_counter(),
                        settings.watch.webhook_min_interval_seconds,
                        fire_on,
                    ):
                        payload = build_payload(
                            {"asn": session.asn, "interface": session.interface},
                            cycle_summary,
                            previous_status,
                            current_status,
                        )
                        if await post_webhook(client, webhook_url, payload, settings.timeouts.http_seconds):
                            last_fired_at = time.perf_counter()
                            session.alerts_fired += 1
                    previous_status = current_status
                    live.update(render_dashboard(session))
                    await asyncio.sleep(next_delay(began, time.perf_counter(), session.interval_seconds))
                    cycle += 1
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass

    path = write_session(session, Path(settings.output.logs_dir))
    console.print(f"Watch session written to {path}")
    return path
