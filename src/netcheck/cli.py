from __future__ import annotations

import asyncio
import os
import platform
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

import httpx
import typer
from rich.console import Console

from netcheck import __version__
from netcheck.compare import diff_reports, load_report, render_diff
from netcheck.config import Settings, load_settings
from netcheck.exporter import build_report, render_markdown, write_report
from netcheck.interpret import (
    assess_vpn,
    gather_vpn_signals,
    latency_findings,
    path_findings,
    speed_findings,
)
from netcheck.ip_geo import dual_stack_mismatch, gather_identity
from netcheck.models import Finding, IpGeo, LocalNet, ModuleResult, SpeedResult
from netcheck.netinfo import collect_local_net, detect_capabilities, is_tunnel_iface
from netcheck.orchestration import gather_modules, run_module, utc_now_iso
from netcheck.probes.dns_leak import collect_dns_leak
from netcheck.probes.latency import ping_fanout, tcp_connect_rtt
from netcheck.probes.traceroute import traceroute
from netcheck.speed import NDT7_CONSENT_NOTICE

app = typer.Typer(add_completion=False, help="Deep network diagnostics.")
console = Console()


@dataclass
class Options:
    mode: str = "auto"
    target_kind: str | None = None
    target_value: str | None = None
    quick: bool = False
    full: bool = False
    extra_host: str | None = None
    speedtest_server: str | None = None
    dnsbl: bool = False
    ndt7: bool = False
    tcp_trace: bool = False


def parse_target(value: str) -> tuple[str, str]:
    text = value.strip()
    if text.upper().startswith("AS") and text[2:].isdigit():
        return "asn", text.upper()
    if text.isdigit():
        return "asn", f"AS{text}"
    if all(part.isdigit() for part in text.split(".")) and text.count(".") == 3:
        return "ip", text
    if ":" in text:
        return "ip", text
    return "domain", text


def _os_timezone() -> str | None:
    # The VPN timezone signal needs an IANA name; Windows has none, so the signal
    # simply stays unobserved there rather than being guessed at.
    if os.environ.get("TZ"):
        return os.environ["TZ"]
    localtime = Path("/etc/localtime")
    if localtime.is_symlink():
        return str(localtime.readlink()).split("zoneinfo/")[-1] or None
    try:
        return Path("/etc/timezone").read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return out


async def _identity(client: httpx.AsyncClient, settings: Settings, options: Options, raw: dict) -> dict:
    token = settings.ipinfo_token.get_secret_value() if settings.ipinfo_token else None
    lookup = options.target_value if options.target_kind in ("ip", "domain") else None
    merged, cf, flags, payloads = await gather_identity(
        client, settings.providers, ip=lookup, ipinfo_token=token
    )
    raw.update(payloads)
    v6 = None
    if options.target_kind is None:
        try:
            transport = httpx.AsyncHTTPTransport(local_address="::")
            async with httpx.AsyncClient(
                transport=transport, timeout=settings.timeouts.http_seconds
            ) as v6_client:
                v6_merged, _cf6, _flags6, _raw6 = await gather_identity(v6_client, settings.providers)
            v6 = v6_merged if v6_merged.ip else None
        except (httpx.HTTPError, OSError):
            v6 = None
    return {
        "egress_v4": merged,
        "egress_v6": v6,
        "cf_trace": cf,
        "dual_stack_note": dual_stack_mismatch(merged, v6),
        "_flags": flags,
    }


async def _bgp_section(client, settings: Settings, asn: str | None, raw: dict):
    if not asn:
        return ModuleResult(name="bgp", status="skipped", warnings=["no ASN was resolved for this target"])
    from netcheck.bgp import collect_bgp

    key = settings.peeringdb_api_key.get_secret_value() if settings.peeringdb_api_key else None
    intel, payloads = await collect_bgp(
        client, settings.providers, Path(settings.output.cache_dir), asn, peeringdb_key=key
    )
    raw.update(payloads)
    return ModuleResult(name="bgp", status="ok", data=intel)


async def _reputation_section(client, settings: Settings, options: Options, geo: IpGeo, raw: dict):
    from netcheck.reputation import (
        build_reputation,
        fetch_abuseipdb,
        fetch_internetdb,
        normalize_internetdb,
        query_dnsbl,
        refresh_netsets,
    )

    if not geo.ip:
        return ModuleResult(name="reputation", status="skipped", warnings=["no egress IP to check"])
    warnings: list[str] = []
    index = await refresh_netsets(client, settings.providers, Path(settings.output.cache_dir))
    payload = await fetch_internetdb(client, settings.providers, geo.ip)
    raw["internetdb"] = payload
    outcomes = None
    if options.dnsbl and geo.ip_version == 4:
        outcomes = await query_dnsbl(geo.ip, settings.dnsbl.zones, settings.timeouts.dns_seconds)
    score = reports = None
    if settings.abuseipdb_api_key:
        abuse = await fetch_abuseipdb(
            client, settings.providers, geo.ip, settings.abuseipdb_api_key.get_secret_value()
        )
        raw["abuseipdb"] = abuse
        data = abuse.get("data") or {}
        score, reports = data.get("abuseConfidenceScore"), data.get("totalReports")
    else:
        warnings.append("ABUSEIPDB_API_KEY not set — abuse score skipped")
    reputation = build_reputation(
        internetdb=normalize_internetdb(payload),
        firehol_hits=index.hits(geo.ip),
        dnsbl_outcomes=outcomes,
        ip_type=geo.ip_type,
        abuseipdb_score=score,
        abuseipdb_reports=reports,
    )
    return ModuleResult(
        name="reputation", status="partial" if warnings else "ok", data=reputation, warnings=warnings
    )


async def _traces(hosts, caps, settings: Settings, cycles: int, options: Options):
    semaphore = asyncio.Semaphore(settings.probing.trace_concurrency)
    return list(
        await asyncio.gather(
            *(
                traceroute(
                    host,
                    caps,
                    max_hops=settings.probing.max_hops,
                    cycles=cycles,
                    timeout=settings.timeouts.subprocess_seconds,
                    semaphore=semaphore,
                    tcp_trace=options.tcp_trace,
                )
                for _label, host in hosts
            )
        )
    )


async def _speed_section(client, settings: Settings, options: Options, idle_rtt_ms: float | None):
    import shutil

    from netcheck.speed import (
        measure_with_bufferbloat,
        run_speed_cascade,
        tier_cloudflare,
        tier_fastcom,
        tier_ndt7,
        tier_ookla,
    )

    cfg = settings.speedtest
    timeout = settings.timeouts.speedtest_seconds
    builders = {
        "ookla_bin": lambda: tier_ookla(
            shutil.which("speedtest") or "speedtest", options.speedtest_server, timeout
        ),
        "cloudflare": lambda: tier_cloudflare(client, cfg, timeout),
        "fastcom": lambda: tier_fastcom(client, cfg, timeout),
        "ndt7": lambda: tier_ndt7(client, cfg, timeout),
    }
    enabled = list(cfg.enabled_tiers) + (["ndt7"] if options.ndt7 else [])
    result = await run_speed_cascade([(name, builders[name]) for name in enabled if name in builders])
    if result.method == "none":
        return ModuleResult(name="speed", status="failed", data=result)

    async def _saturate_down() -> None:
        await client.get(
            f"{cfg.cloudflare_base_url}/__down", params={"bytes": cfg.download_sizes_bytes[-1]}, timeout=timeout
        )

    async def _saturate_up() -> None:
        await client.post(
            f"{cfg.cloudflare_base_url}/__up", content=b"\x00" * cfg.upload_sizes_bytes[-1], timeout=timeout
        )

    async def _probe() -> float | None:
        return await tcp_connect_rtt("1.1.1.1", timeout=settings.probing.ping_timeout_seconds)

    result = await measure_with_bufferbloat(
        result,
        idle_rtt_ms=idle_rtt_ms if result.idle_rtt_ms is None else result.idle_rtt_ms,
        bands=settings.thresholds.bufferbloat_ms,
        run_download=_saturate_down,
        run_upload=_saturate_up,
        probe=_probe,
        interval=cfg.bufferbloat_probe_interval_seconds,
    )
    return ModuleResult(name="speed", status="ok", data=result)


async def diagnose(settings: Settings, options: Options) -> tuple[dict, str, Path, Path]:
    started_at = utc_now_iso()
    caps = detect_capabilities()
    timeouts = settings.timeouts
    modules: dict[str, ModuleResult] = {}
    raw: dict[str, Any] = {}

    async with httpx.AsyncClient(
        timeout=timeouts.http_seconds,
        follow_redirects=True,
        http2=True,
        headers={"User-Agent": f"netcheck/{__version__}"},
    ) as client:
        # Phase 1 — local facts and identity. Blocking: everything below needs the ASN.
        modules["connection"] = await run_module(
            "connection", asyncio.to_thread(collect_local_net), timeout=timeouts.module_seconds
        )
        local = modules["connection"].data or LocalNet()
        modules["ip_geo"] = await run_module(
            "ip_geo", _identity(client, settings, options, raw), timeout=timeouts.module_seconds
        )
        bundle = modules["ip_geo"].data or {}
        flags = bundle.pop("_flags", {}) if isinstance(bundle, dict) else {}
        geo = bundle.get("egress_v4") or IpGeo()
        if bundle.get("dual_stack_note"):
            modules["ip_geo"].warnings.append(bundle["dual_stack_note"])
        asn = geo.asn if options.target_kind != "asn" else options.target_value

        # Phase 2 — bgp || reputation || dns_leak
        bgp_result, rep_result, dns_result = await gather_modules(
            run_module("bgp", _bgp_section(client, settings, asn, raw), timeout=timeouts.module_seconds),
            run_module(
                "reputation", _reputation_section(client, settings, options, geo, raw), timeout=timeouts.module_seconds
            ),
            run_module(
                "dns_leak",
                collect_dns_leak(local, asn, settings.providers.cymru_origin_zone, timeouts.dns_seconds),
                timeout=timeouts.module_seconds,
            ),
        )
        modules["bgp"], modules["reputation"] = bgp_result, rep_result
        signals = gather_vpn_signals(
            local=local,
            geo=geo,
            cf=bundle.get("cf_trace"),
            dns_leak=dns_result.data,
            pdb_info_type=getattr(bgp_result.data, "pdb_info_type", None),
            os_timezone=_os_timezone(),
            provider_flags=flags,
        )
        modules["vpn_assessment"] = ModuleResult(
            name="vpn_assessment",
            status="ok" if dns_result.status == "ok" else "partial",
            data=assess_vpn(
                signals,
                settings.thresholds.vpn_confidence,
                tunnel_iface=local.iface_name if is_tunnel_iface(local.iface_name or "") else None,
                dns_leak=dns_result.data,
            ),
            errors=dns_result.errors,
            started_at=dns_result.started_at,
            duration_ms=dns_result.duration_ms,
        )

        # Phase 3 — latency || traceroute, both bounded
        hosts = [(h.label, h.host) for h in settings.probing.reference_hosts]
        if not options.quick:
            hosts += [(h.label, h.host) for h in settings.probing.service_hosts]
        if options.extra_host:
            hosts.append(("target-host", options.extra_host))
        if options.target_kind in ("ip", "domain"):
            hosts.append(("target", options.target_value))
        count = settings.probing.quick_ping_count if options.quick else settings.probing.ping_count
        cycles = settings.probing.quick_mtr_cycles if options.quick else settings.probing.mtr_cycles
        modules["latency"], modules["path"] = await gather_modules(
            run_module(
                "latency",
                ping_fanout(
                    hosts,
                    caps,
                    count,
                    settings.probing.ping_interval_seconds,
                    settings.probing.ping_timeout_seconds,
                ),
                timeout=timeouts.subprocess_seconds,
            ),
            run_module("path", _traces(hosts, caps, settings, cycles, options), timeout=timeouts.subprocess_seconds),
        )

        # Phase 4 — speed, exclusive: nothing else is in flight at this point.
        pings = modules["latency"].data or []
        idle_rtt = min((p.avg_ms for p in pings if p.avg_ms is not None), default=None)
        skip_speed = options.quick or (options.mode == "target" and not options.speedtest_server)
        if skip_speed:
            modules["speed"] = ModuleResult(
                name="speed",
                status="skipped",
                warnings=["speedtest skipped: --quick" if options.quick else "speedtest skipped in target mode"],
            )
        else:
            modules["speed"] = await run_module(
                "speed", _speed_section(client, settings, options, idle_rtt), timeout=timeouts.speedtest_seconds
            )

    # Phase 5 — interpret
    speed = modules["speed"].data or SpeedResult()
    findings = _dedupe(
        latency_findings(pings, settings.thresholds)
        + [f for trace in (modules["path"].data or []) for f in path_findings(trace)]
        + speed_findings(speed, settings.thresholds.bufferbloat_ms)
    )

    # Phase 6 — export
    meta = {
        "run_id": uuid.uuid4().hex[:12],
        "started_at": started_at,
        "finished_at": utc_now_iso(),
        "mode": options.mode,
        "target": options.target_value,
        "flags": {
            "quick": options.quick,
            "full": options.full,
            "dnsbl": options.dnsbl,
            "ndt7": options.ndt7,
            "tcp_trace": options.tcp_trace,
        },
        "host_os": f"{platform.system()} {platform.release()}",
        "capabilities": caps,
    }
    report = build_report(meta, modules, findings, raw)
    markdown = render_markdown(report, emoji=settings.output.emoji)
    json_path, md_path = write_report(report, markdown, Path(settings.output.logs_dir))
    return report, markdown, json_path, md_path


@app.command()
def run(
    full: bool = typer.Option(False, "--full", help="Full run: speedtest and full MTR cycles."),
    quick: bool = typer.Option(False, "--quick", help="Express run: reference hosts only, no speedtest."),
    target: Optional[str] = typer.Option(None, "--target", help="Investigate AS<n>, an IP or a domain."),
    target_host: Optional[str] = typer.Option(None, "--target-host", help="Extra host for ping/traceroute."),
    speedtest_server: Optional[str] = typer.Option(None, "--speedtest-server", help="Pin the speedtest server."),
    watch: bool = typer.Option(False, "--watch", help="Continuous monitoring with a live dashboard."),
    compare: Optional[Tuple[Path, Path]] = typer.Option(None, "--compare", help="Diff two saved JSON reports."),
    dnsbl: bool = typer.Option(False, "--dnsbl", help="Also query classic DNSBL zones."),
    ndt7: bool = typer.Option(False, "--ndt7", help="Add the M-Lab NDT7 speedtest tier (publishes your IP)."),
    tcp_trace: bool = typer.Option(False, "--tcp-trace", help="Add a scapy TCP-SYN traceroute tier."),
) -> None:
    settings = load_settings()
    if compare:
        before, after = load_report(compare[0]), load_report(compare[1])
        console.print(render_diff(diff_reports(before, after), emoji=settings.output.emoji))
        raise typer.Exit(0)

    kind, value = parse_target(target) if target else (None, None)
    options = Options(
        mode="target" if target else "auto",
        target_kind=kind,
        target_value=value,
        quick=quick and not full,
        full=full,
        extra_host=target_host,
        speedtest_server=speedtest_server,
        dnsbl=dnsbl,
        ndt7=ndt7,
        tcp_trace=tcp_trace,
    )
    if ndt7:
        console.print(f"[yellow]{NDT7_CONSENT_NOTICE}[/yellow]")
        if sys.stdin.isatty() and not typer.confirm("Continue with NDT7?", default=False):
            options.ndt7 = False
    if tcp_trace:
        console.print(
            "[yellow]--tcp-trace needs Npcap (Windows) or root (Unix) and the `tcptrace` extra; "
            "if it cannot run, the cascade falls through to the normal tiers.[/yellow]"
        )
    if watch:
        from netcheck.watch import run_watch

        asyncio.run(run_watch(settings, options))
        raise typer.Exit(0)

    console.print(f"netcheck {__version__} · {options.mode} mode · {platform.system()}")
    report, _markdown, json_path, md_path = asyncio.run(diagnose(settings, options))
    interpretation = report["interpretation"]
    console.print(
        f"Verdict: [bold]{interpretation['overall_status']}[/bold] "
        f"({interpretation['overall_score']}/100) — {interpretation['summary_text']}"
    )
    console.print(f"Report written to {md_path}\n                 {json_path}")


def main() -> None:
    app()
