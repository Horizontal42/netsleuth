from __future__ import annotations

import asyncio
import os
import platform
import socket
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import psutil
import typer
from rich.console import Console

from netsleuth import __version__
from netsleuth.compare import diff_reports, load_report, render_diff
from netsleuth.config import FORMAT_EXTENSIONS, Settings, load_settings
from netsleuth.exporter import (
    build_report,
    dump_json,
    egress_asn,
    render_markdown,
    report_filename,
    write_report,
)
from netsleuth.iface import resolve_bind_target
from netsleuth.interpret import (
    assess_vpn,
    dns_advanced_findings,
    dpi_findings,
    gather_vpn_signals,
    latency_findings,
    path_diversity_findings,
    path_findings,
    prefix_findings,
    speed_findings,
    tls_findings,
)
from netsleuth.ip_geo import dual_stack_mismatch, gather_identity
from netsleuth.models import (
    BindTarget,
    Finding,
    IpGeo,
    LocalNet,
    ModuleResult,
    ProbeError,
    SpeedResult,
    VpnContext,
)
from netsleuth.netinfo import (
    collect_local_net,
    detect_capabilities,
    is_tunnel_iface,
)
from netsleuth.orchestration import gather_modules, run_module, utc_now_iso
from netsleuth.probes.dns_leak import collect_dns_leak
from netsleuth.probes.latency import ping_fanout, tcp_connect_rtt
from netsleuth.probes.traceroute import filter_trace_tiers, tier_order, traceroute
from netsleuth.speed import NDT7_CONSENT_NOTICE

if sys.platform == "win32":
    # A legacy console codepage (e.g. cp1251) cannot encode the emoji badges and
    # Unicode punctuation this CLI prints; forcing UTF-8 here avoids a hard crash
    # in rich's Windows renderer on every non-ASCII character.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

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
    tls: bool = False
    dns_advanced: bool = False
    path_diversity: bool = False
    prefix_bench: bool = False
    dpi_target: str | None = None
    formats: frozenset[str] = frozenset({"md"})
    interface: str | None = None
    bind: BindTarget | None = None


def parse_formats(
    values: list[str], ru: bool, json_flag: bool, default: frozenset[str]
) -> frozenset[str]:
    tokens = [t.strip().lower() for raw in values for t in raw.split(",") if t.strip()]
    if ru:
        tokens.append("ru-md")
    if json_flag:
        tokens.append("json")
    if not tokens:
        return default
    if "none" in tokens:
        if len(set(tokens)) > 1:
            raise typer.BadParameter("'none' cannot be combined with other formats.")
        return frozenset()
    if "all" in tokens:
        return frozenset(FORMAT_EXTENSIONS)
    unknown = sorted(set(tokens) - set(FORMAT_EXTENSIONS))
    if unknown:
        raise typer.BadParameter(
            f"unknown format(s) {unknown}; expected one of {sorted(FORMAT_EXTENSIONS)}, 'all' or 'none'"
        )
    return frozenset(tokens)


def format_siblings(
    formats: frozenset[str], md_name: str, ru_md_name: str
) -> tuple[str | None, str | None]:
    if "md" in formats and "ru-md" in formats:
        return ru_md_name, md_name
    return None, None


def _is_private_or_reserved_ip(ip: str) -> bool:
    """Проверяет, является ли IP адрес частным или зарезервированным.

    Args:
        ip: IP адрес для проверки

    Returns:
        True если IP частный/зарезервированный, False иначе
    """
    forbidden_prefixes = [
        "127.",      # localhost
        "0.",        # current network
        "10.",       # private class A
        "192.168.",  # private class C
        "172.16.",   # private class B (start)
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "169.254.",  # link-local
        "224.",      # multicast
        "240.",      # reserved
        "::1",       # IPv6 localhost
        "fe80:",     # IPv6 link-local
        "fc00:",     # IPv6 unique local
        "fd00:",     # IPv6 unique local
    ]
    return any(ip.startswith(prefix) for prefix in forbidden_prefixes)


def parse_target(value: str) -> tuple[str, str]:
    """Парсит и валидирует целевой хост для диагностики.

    Args:
        value: Строка с целью (IP, домен, ASN)

    Returns:
        Кортеж (тип_цели, значение)

    Raises:
        typer.BadParameter: Если цель невалидна или запрещена
    """
    text = value.strip()

    # Проверка на частные/зарезервированные IP
    if all(part.isdigit() for part in text.split(".")) and text.count(".") == 3:
        if _is_private_or_reserved_ip(text):
            raise typer.BadParameter(
                f"Target IP {text} is private or reserved; "
                "please use a public IP address or domain name"
            )

    if text.upper().startswith("AS") and text[2:].isdigit():
        return "asn", text.upper()
    if text.isdigit():
        return "asn", f"AS{text}"
    if all(part.isdigit() for part in text.split(".")) and text.count(".") == 3:
        return "ip", text
    if ":" in text:
        # IPv6 проверка
        if _is_private_or_reserved_ip(text):
            raise typer.BadParameter(
                f"Target IPv6 {text} is private or reserved; "
                "please use a public IPv6 address"
            )
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
    own_network = options.target_kind in (None, "asn")
    bind_v4 = options.bind.ipv4 if options.bind else "0.0.0.0"
    warnings: list[str] = []
    if own_network:
        # The shared client has no address family pinned, so on a dual-stack host it can
        # silently connect over IPv6 (OS/happy-eyeballs preference) and hand back an IPv6
        # literal mislabeled as egress_v4. Force IPv4 here the same way egress_v6 is forced
        # below, so the two slots can never both resolve to the same protocol.
        try:
            transport = httpx.AsyncHTTPTransport(local_address=bind_v4)
            async with httpx.AsyncClient(
                transport=transport, timeout=settings.timeouts.http_seconds
            ) as v4_client:
                merged, cf, flags, payloads = await gather_identity(
                    v4_client, settings.providers, ip=lookup, ipinfo_token=token
                )
        except (httpx.HTTPError, OSError):
            merged, cf, flags, payloads = await gather_identity(
                client, settings.providers, ip=lookup, ipinfo_token=token
            )
    else:
        merged, cf, flags, payloads = await gather_identity(
            client, settings.providers, ip=lookup, ipinfo_token=token
        )
    raw.update(payloads)
    v6 = None
    if own_network and options.bind and options.bind.ipv6 is None:
        warnings.append(
            f"IPv6 identity skipped: forced interface {options.bind.iface_name!r} has no global IPv6 address"
        )
    elif own_network:
        try:
            transport = httpx.AsyncHTTPTransport(local_address=options.bind.ipv6 if options.bind else "::")
            async with httpx.AsyncClient(
                transport=transport, timeout=settings.timeouts.http_seconds
            ) as v6_client:
                v6_merged, _cf6, _flags6, _raw6 = await gather_identity(v6_client, settings.providers)
            v6 = v6_merged if v6_merged.ip else None
        except (httpx.HTTPError, OSError):
            v6 = None
    dual_stack = dual_stack_mismatch(merged, v6)
    return {
        "egress_v4": merged,
        "egress_v6": v6,
        "cf_trace": cf,
        "dual_stack_note": dual_stack[0] if dual_stack else None,
        "dual_stack_note_ru": dual_stack[1] if dual_stack else None,
        "_flags": flags,
        "_warnings": warnings,
    }


async def _bgp_section(client, settings: Settings, asn: str | None, raw: dict):
    if not asn:
        return ModuleResult(name="bgp", status="skipped", warnings=["no ASN was resolved for this target"])
    from netsleuth.bgp import collect_bgp

    key = settings.peeringdb_api_key.get_secret_value() if settings.peeringdb_api_key else None
    intel, payloads = await collect_bgp(
        client, settings.providers, Path(settings.output.cache_dir), asn, peeringdb_key=key
    )
    raw.update(payloads)
    return ModuleResult(name="bgp", status="ok", data=intel)


async def _reputation_section(client, settings: Settings, options: Options, geo: IpGeo, raw: dict):
    from netsleuth.reputation import (
        ReputationContext,
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
        ReputationContext(
            internetdb=normalize_internetdb(payload),
            firehol_hits=index.hits(geo.ip),
            dnsbl_outcomes=outcomes,
            ip_type=geo.ip_type,
            abuseipdb_score=score,
            abuseipdb_reports=reports,
        )
    )
    return ModuleResult(
        name="reputation", status="partial" if warnings else "ok", data=reputation, warnings=warnings
    )


async def _tls_section(settings: Settings, options: Options) -> ModuleResult:
    if not options.tls:
        return ModuleResult(name="tls", status="skipped", warnings=["tls probe skipped: not requested"])
    from netsleuth.probes.tls_rtt import tls_fanout

    cfg = settings.tls
    targets = [(t.label, t.host) for t in cfg.targets]
    results = await tls_fanout(
        targets,
        port=cfg.port,
        timeout=settings.timeouts.http_seconds,
        concurrency=cfg.concurrency,
        source_ip=options.bind.ipv4 if options.bind else None,
    )
    return ModuleResult(name="tls", status="ok", data=results)


async def _dns_advanced_section(client, settings: Settings, options: Options) -> ModuleResult:
    if not options.dns_advanced:
        return ModuleResult(
            name="dns_advanced", status="skipped", warnings=["dns advanced probe skipped: not requested"]
        )
    from netsleuth.probes.dns_advanced import collect_dns_advanced

    cfg = settings.dns_advanced
    adv = await collect_dns_advanced(
        client, cfg.control_names, cfg.doh_endpoints, cfg.bogus_resolver_ip, cfg.bogus_probe_name, settings.timeouts.dns_seconds
    )
    return ModuleResult(name="dns_advanced", status="ok", data=adv)


async def _path_diversity_section(client, settings: Settings, options: Options, client_country: str | None) -> ModuleResult:
    if not options.path_diversity:
        return ModuleResult(
            name="path_diversity", status="skipped", warnings=["path diversity probe skipped: not requested"]
        )
    from netsleuth.probes.bgp_path import collect_path_diversity

    cfg = settings.path_diversity
    targets = [(t.label, t.host) for t in cfg.targets]
    pd = await collect_path_diversity(
        client,
        targets,
        client_country,
        max_targets=cfg.max_targets,
        timeout=settings.timeouts.http_seconds,
        source_ip=options.bind.ipv4 if options.bind else None,
    )
    return ModuleResult(name="path_diversity", status="ok", data=pd)


async def _prefix_bench_section(caps, settings: Settings, options: Options, bgp) -> ModuleResult:
    if not options.prefix_bench:
        return ModuleResult(
            name="prefix_benchmark", status="skipped", warnings=["prefix benchmark skipped: not requested"]
        )
    if not bgp or not bgp.announced_prefixes:
        return ModuleResult(
            name="prefix_benchmark", status="skipped", warnings=["prefix benchmark skipped: no announced prefixes"]
        )
    from netsleuth.probes.prefix_benchmark import benchmark_prefixes

    cfg = settings.prefix_bench
    bench = await benchmark_prefixes(
        bgp.announced_prefixes,
        caps,
        limit=cfg.max_prefixes,
        count=cfg.ping_count,
        interval=settings.probing.ping_interval_seconds,
        timeout=settings.probing.ping_timeout_seconds,
        concurrency=cfg.concurrency,
        offset=cfg.host_offset,
        family=cfg.family,
        source_ip=options.bind.ipv4 if options.bind else None,
    )
    bench.asn = bgp.asn
    return ModuleResult(name="prefix_benchmark", status="ok", data=bench)


async def _dpi_section(settings: Settings, options: Options) -> ModuleResult:
    if not options.dpi_target:
        return ModuleResult(
            name="dpi_check", status="skipped", warnings=["dpi check skipped: no explicit --my-server target"]
        )
    from netsleuth.probes.dpi_check import check_dpi

    target = options.dpi_target
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(target, None)
        resolved = infos[0][4][0]
    except (OSError, IndexError) as exc:
        return ModuleResult(
            name="dpi_check",
            status="failed",
            errors=[ProbeError(source="dpi_check", kind="unavailable", message=f"could not resolve {target}: {exc}")],
        )
    cfg = settings.dpi_check
    console.print(
        f"[yellow]--my-server opens TCP connections to {target} ({resolved}) on {len(cfg.ports)} ports. "
        "Use it only on hosts you own or are authorised to test.[/yellow]"
    )
    result = await check_dpi(
        target,
        resolved,
        cfg.ports,
        timeout=cfg.connect_timeout_seconds,
        delay=cfg.delay_between_ports_seconds,
        concurrency=cfg.concurrency,
        source_ip=options.bind.ipv4 if options.bind else None,
    )
    return ModuleResult(name="dpi_check", status="ok", data=result)


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
                    source_ip=options.bind.ipv4 if options.bind else None,
                )
                for _label, host in hosts
            )
        )
    )


async def _speed_section(client, settings: Settings, options: Options, idle_rtt_ms: float | None):
    import shutil

    from netsleuth.speed import (
        measure_with_bufferbloat,
        run_speed_cascade,
        tier_cloudflare,
        tier_fastcom,
        tier_ndt7,
        tier_ookla,
    )

    cfg = settings.speedtest
    timeout = settings.timeouts.speedtest_seconds
    bind = options.bind
    builders = {
        "ookla_bin": lambda: tier_ookla(
            shutil.which("speedtest") or "speedtest",
            options.speedtest_server,
            timeout,
            iface_name=bind.iface_name if bind else None,
            ipv4=bind.ipv4 if bind else None,
        ),
        "cloudflare": lambda: tier_cloudflare(client, cfg, timeout),
        "fastcom": lambda: tier_fastcom(client, cfg, timeout),
        "ndt7": lambda: tier_ndt7(client, cfg, timeout, source_ip=bind.ipv4 if bind else None),
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


async def diagnose(settings: Settings, options: Options) -> tuple[dict, list[Path]]:
    started_at = utc_now_iso()
    caps = detect_capabilities()
    timeouts = settings.timeouts
    modules: dict[str, ModuleResult] = {}
    raw: dict[str, Any] = {}

    client_transport = (
        httpx.AsyncHTTPTransport(local_address=options.bind.ipv4, http2=True) if options.bind else None
    )
    async with httpx.AsyncClient(
        transport=client_transport,
        timeout=timeouts.http_seconds,
        follow_redirects=True,
        http2=True,
        headers={"User-Agent": f"netsleuth/{__version__}"},
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
        identity_warnings = bundle.pop("_warnings", []) if isinstance(bundle, dict) else []
        geo = bundle.get("egress_v4") or IpGeo()
        if bundle.get("dual_stack_note"):
            modules["ip_geo"].warnings.append(bundle["dual_stack_note"])
        modules["ip_geo"].warnings.extend(identity_warnings)
        asn = geo.asn if options.target_kind != "asn" else options.target_value

        # Phase 2 — bgp || reputation || dns_leak || dns_advanced || path_diversity
        bgp_result, rep_result, dns_result, dns_advanced_result, path_diversity_result = await gather_modules(
            run_module("bgp", _bgp_section(client, settings, asn, raw), timeout=timeouts.module_seconds),
            run_module(
                "reputation", _reputation_section(client, settings, options, geo, raw), timeout=timeouts.module_seconds
            ),
            run_module(
                "dns_leak",
                collect_dns_leak(local, asn, settings.providers.cymru_origin_zone, timeouts.dns_seconds),
                timeout=timeouts.module_seconds,
            ),
            run_module("dns_advanced", _dns_advanced_section(client, settings, options), timeout=timeouts.module_seconds),
            run_module(
                "path_diversity",
                _path_diversity_section(client, settings, options, geo.country_code),
                timeout=timeouts.module_seconds,
            ),
        )
        modules["bgp"], modules["reputation"] = bgp_result, rep_result
        modules["dns_advanced"], modules["path_diversity"] = dns_advanced_result, path_diversity_result
        ctx = VpnContext(
            local=local,
            geo=geo,
            cf=bundle.get("cf_trace"),
            dns_leak=dns_result.data,
            pdb_info_type=getattr(bgp_result.data, "pdb_info_type", None),
            os_timezone=_os_timezone(),
            provider_flags=flags,
        )
        signals = gather_vpn_signals(ctx)
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
        modules["latency"], modules["path"], modules["tls"] = await gather_modules(
            run_module(
                "latency",
                ping_fanout(
                    hosts,
                    caps,
                    count,
                    settings.probing.ping_interval_seconds,
                    settings.probing.ping_timeout_seconds,
                    source_ip=options.bind.ipv4 if options.bind else None,
                ),
                timeout=timeouts.subprocess_seconds,
            ),
            run_module("path", _traces(hosts, caps, settings, cycles, options), timeout=timeouts.subprocess_seconds),
            run_module("tls", _tls_section(settings, options), timeout=timeouts.module_seconds),
        )

        # Phase 3b — prefix benchmark and DPI check, opt-in and exclusive: each is a
        # single-target/self-scoped probe that should not share the wire with the
        # reference-host latency fanout above.
        modules["prefix_benchmark"] = await run_module(
            "prefix_benchmark",
            _prefix_bench_section(caps, settings, options, bgp_result.data),
            timeout=timeouts.subprocess_seconds,
        )
        modules["dpi_check"] = await run_module(
            "dpi_check", _dpi_section(settings, options), timeout=timeouts.module_seconds
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
    l7_findings: list[Finding] = list(tls_findings(modules["tls"].data or [], settings.thresholds))
    if modules["prefix_benchmark"].data is not None:
        l7_findings += prefix_findings(modules["prefix_benchmark"].data, settings.thresholds)
    if modules["dpi_check"].data is not None:
        l7_findings += dpi_findings(modules["dpi_check"].data)
    if modules["dns_advanced"].data is not None:
        l7_findings += dns_advanced_findings(modules["dns_advanced"].data, settings.thresholds)
    if modules["path_diversity"].data is not None:
        l7_findings += path_diversity_findings(modules["path_diversity"].data)
    findings = _dedupe(
        latency_findings(pings, settings.thresholds)
        + [f for trace in (modules["path"].data or []) for f in path_findings(trace)]
        + speed_findings(speed, settings.thresholds.bufferbloat_ms)
        + l7_findings
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
            "interface": options.interface,
            "tls": options.tls,
            "dns_advanced": options.dns_advanced,
            "path_diversity": options.path_diversity,
            "prefix_bench": options.prefix_bench,
        },
        "dpi_target": options.dpi_target,
        "formats": sorted(options.formats),
        "host_os": f"{platform.system()} {platform.release()}",
        "capabilities": caps,
    }
    if options.bind:
        _kept, dropped = filter_trace_tiers(
            tier_order(caps, options.tcp_trace), caps.os_name, forced_v4=bool(options.bind.ipv4)
        )
        meta["interface"] = {
            "requested": options.bind.requested,
            "resolved_iface": options.bind.iface_name,
            "bind_ipv4": options.bind.ipv4,
            "bind_ipv6": options.bind.ipv6,
            "os_default_iface": local.iface_name,
            "os_default_ipv4": local.local_ipv4,
            "dropped_backends": dropped,
        }
    report = build_report(meta, modules, findings, raw)
    asn = meta.get("target") or egress_asn(report)
    md_name = report_filename(asn, started_at, "md")
    ru_md_name = report_filename(asn, started_at, "ru.md")
    sibling_for_md, sibling_for_ru = format_siblings(options.formats, md_name, ru_md_name)
    artifacts: dict[str, str] = {}
    if "md" in options.formats:
        artifacts["md"] = render_markdown(report, emoji=settings.output.emoji, lang="en", sibling=sibling_for_md)
    if "ru-md" in options.formats:
        artifacts["ru-md"] = render_markdown(report, emoji=settings.output.emoji, lang="ru", sibling=sibling_for_ru)
    if "json" in options.formats:
        artifacts["json"] = dump_json(report)
    paths = write_report(report, artifacts, Path(settings.output.logs_dir))
    return report, paths


def _check_ndt7_consent(settings: Settings) -> bool:
    consent_marker = Path(settings.output.cache_dir) / "ndt7_consent"
    if consent_marker.exists():
        return True

    console.print(f"[yellow]{NDT7_CONSENT_NOTICE}[/yellow]")
    if not sys.stdin.isatty():
        return True

    if typer.confirm("Continue with NDT7?", default=False):
        consent_marker.parent.mkdir(parents=True, exist_ok=True)
        consent_marker.write_text("consented\n", encoding="utf-8")
        return True

    return False


@app.command()
def run(
    full: bool = typer.Option(False, "--full", help="Full run: speedtest and full MTR cycles."),
    quick: bool = typer.Option(False, "--quick", help="Express run: reference hosts only, no speedtest."),
    target: str | None = typer.Option(None, "--target", help="Investigate AS<n>, an IP or a domain."),
    target_host: str | None = typer.Option(None, "--target-host", help="Extra host for ping/traceroute."),
    speedtest_server: str | None = typer.Option(None, "--speedtest-server", help="Pin the speedtest server."),
    watch: bool = typer.Option(False, "--watch", help="Continuous monitoring with a live dashboard."),
    compare: tuple[Path, Path] | None = typer.Option(
        None, "--compare", help="Diff two saved JSON reports — reads reports produced with --format json."
    ),
    dnsbl: bool = typer.Option(False, "--dnsbl", help="Also query classic DNSBL zones."),
    ndt7: bool = typer.Option(False, "--ndt7", help="Add the M-Lab NDT7 speedtest tier (publishes your IP)."),
    tcp_trace: bool = typer.Option(False, "--tcp-trace", help="Add a scapy TCP-SYN traceroute tier."),
    tls: bool = typer.Option(False, "--tls", help="Measure TCP/TLS handshake RTT and TTFB to reference services."),
    dns_advanced: bool = typer.Option(
        False, "--dns-advanced", help="Compare system DNS vs DoH and probe for a transparent DNS proxy."
    ),
    path_diversity: bool = typer.Option(
        False, "--path-diversity", help="Compare client geo against the Cloudflare edge PoP actually serving traffic."
    ),
    prefix_bench: bool = typer.Option(
        False,
        "--prefix-bench",
        help="Ping the first host of a handful of your own AS's announced prefixes to find the lowest-latency PoP.",
    ),
    my_server: str | None = typer.Option(
        None,
        "--my-server",
        help="Check a server YOU OWN for TCP port blocking / RST injection. Single host only — never a CIDR or someone else's server.",
    ),
    format_: list[str] = typer.Option(
        [],
        "--format",
        help=(
            "Which report artifacts to write: md, ru-md, json, all, none. Repeatable and "
            "comma-separated (--format md,json). Any --format replaces the default instead of "
            "adding to it. Ignored with --watch and --compare."
        ),
    ),
    ru: bool = typer.Option(False, "--ru", help="Shorthand for --format ru-md."),
    json_flag: bool = typer.Option(False, "--json", help="Shorthand for --format json."),
    interface: str | None = typer.Option(
        None,
        "--interface",
        help="Force outbound probing through this adapter (name or IP), instead of the OS default route.",
    ),
) -> None:
    settings = load_settings()
    if compare:
        before, after = load_report(compare[0]), load_report(compare[1])
        console.print(render_diff(diff_reports(before, after), emoji=settings.output.emoji))
        raise typer.Exit(0)

    if my_server and "/" in my_server:
        raise typer.BadParameter(
            "this is a single-host self-diagnostic, not a network scanner", param_hint="--my-server"
        )
    kind, value = parse_target(target) if target else (None, None)
    formats = parse_formats(format_, ru=ru, json_flag=json_flag, default=frozenset(settings.output.formats))
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
        tls=tls or full,
        dns_advanced=dns_advanced or full,
        path_diversity=path_diversity or full,
        prefix_bench=prefix_bench,
        dpi_target=my_server,
        formats=formats,
    )
    if interface:
        addrs_by_iface = {
            name: [(a.family, a.address.split("%")[0]) for a in addrs]
            for name, addrs in psutil.net_if_addrs().items()
        }
        up_by_iface = {name: stats.isup for name, stats in psutil.net_if_stats().items()}
        bind = resolve_bind_target(interface, addrs_by_iface, up_by_iface)
        if bind.error:
            raise typer.BadParameter(bind.error, param_hint="--interface")
        options.interface = interface
        options.bind = bind
        if bind.ipv4:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind((bind.ipv4, 0))
                probe.connect(("1.1.1.1", 53))
            except OSError:
                console.print(
                    f"[yellow]--interface {bind.iface_name}: no route to the internet from this "
                    "address yet — continuing, this run may show every module as unreachable.[/yellow]"
                )
            finally:
                probe.close()
    if ndt7:
        options.ndt7 = _check_ndt7_consent(settings)
    if tcp_trace:
        console.print(
            "[yellow]--tcp-trace needs Npcap (Windows) or root (Unix) and the `tcptrace` extra; "
            "if it cannot run, the cascade falls through to the normal tiers.[/yellow]"
        )
    if watch:
        from netsleuth.watch import run_watch

        asyncio.run(run_watch(settings, options))
        raise typer.Exit(0)

    console.print(f"netsleuth {__version__} · {options.mode} mode · {platform.system()}")
    report, paths = asyncio.run(diagnose(settings, options))
    interpretation = report["interpretation"]
    console.print(
        f"Verdict: [bold]{interpretation['overall_status']}[/bold] "
        f"({interpretation['overall_score']}/100) — {interpretation['summary_text']}"
    )
    if not paths:
        console.print("No report written (--format none).")
    else:
        label = "Report written to"
        for path in paths:
            console.print(f"{label} {path}")
            label = " " * len("Report written to")


def main() -> None:
    app()
