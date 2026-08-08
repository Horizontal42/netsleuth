from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from netcheck.interpret import overall_verdict
from netcheck.models import Finding, ModuleResult, to_jsonable

SCHEMA_VERSION = 1
SECTION_ORDER = (
    "connection",
    "ip_geo",
    "vpn_assessment",
    "bgp",
    "reputation",
    "latency",
    "path",
    "speed",
)

_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_name(value: str | None, fallback: str = "unknown") -> str:
    cleaned = _UNSAFE_NAME_RE.sub("_", (value or "").strip()).strip("._")
    return cleaned[:32] or fallback


def compact_timestamp(iso: str) -> str:
    # Windows forbids ':' in filenames, so the stamp is the compact ISO form.
    return re.sub(r"[-:]", "", (iso or "").strip()) or "unknown"


def report_filename(asn: str | None, started_at: str, extension: str) -> str:
    return f"report_{sanitize_name(asn)}_{compact_timestamp(started_at)}.{extension.lstrip('.')}"


def flatten_errors(modules: dict[str, ModuleResult]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for section, result in modules.items():
        for error in result.errors:
            entry = to_jsonable(error)
            entry["module"] = result.name or section
            flat.append(entry)
    return flat


def build_report(
    meta: dict[str, Any],
    modules: dict[str, ModuleResult],
    findings: list[Finding],
    raw: dict[str, Any],
) -> dict[str, Any]:
    status, score, summary = overall_verdict(findings)
    report: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "meta": to_jsonable(meta)}
    for section in SECTION_ORDER:
        result = modules.get(section) or ModuleResult(name=section, status="skipped")
        report[section] = to_jsonable(result)
    report["interpretation"] = {
        "overall_status": status,
        "overall_score": score,
        "summary_text": summary,
        "findings": to_jsonable(findings),
    }
    report["errors"] = flatten_errors(modules)
    report["raw"] = to_jsonable(raw)
    return report


def dump_json(report: dict[str, Any]) -> str:
    return json.dumps(to_jsonable(report), allow_nan=False, ensure_ascii=False, indent=2)


def atomic_write(path: Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def egress_asn(report: dict[str, Any]) -> str | None:
    data = (report.get("ip_geo") or {}).get("data") or {}
    return ((data.get("egress_v4") or {}) if isinstance(data, dict) else {}).get("asn")


def write_report(report: dict[str, Any], markdown: str, logs_dir: Path) -> tuple[Path, Path]:
    started = (report.get("meta") or {}).get("started_at", "")
    asn = egress_asn(report)
    base = Path(logs_dir)
    json_path = atomic_write(base / report_filename(asn, started, "json"), dump_json(report))
    md_path = atomic_write(base / report_filename(asn, started, "md"), markdown)
    return json_path, md_path


from netcheck.interpret import bufferbloat_consequence

SPARK_CHARS = "▁▂▃▅▇"
_BADGES = {"ok": "🟢", "info": "🟢", "warn": "🟡", "crit": "🔴"}
_SEVERITY_RANK = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
_LOSS_JUMP_PCT = 20.0


def sparkline(values: list[float | None]) -> str:
    numbers = [v for v in values if v is not None]
    if not numbers:
        return ""
    low, high = min(numbers), max(numbers)
    span = high - low
    out: list[str] = []
    for value in values:
        if value is None:
            out.append(" ")
        elif span <= 0:
            out.append(SPARK_CHARS[0])
        else:
            index = int((value - low) / span * (len(SPARK_CHARS) - 1))
            out.append(SPARK_CHARS[index])
    return "".join(out)


def badge(severity: str, emoji: bool) -> str:
    return _BADGES.get(severity, "⚪") if emoji else f"[{severity}]"


def first_loss_jump(hops: list[dict]) -> int | None:
    for index, hop in enumerate(hops[:-1]):
        following = hops[index + 1]
        if hop.get("loss_pct", 0.0) >= _LOSS_JUMP_PCT and following.get("loss_pct", 0.0) >= _LOSS_JUMP_PCT:
            return hop.get("ttl")
    return None


def _module(report: dict, section: str) -> dict:
    return report.get(section) or {}


def _data(report: dict, section: str) -> Any:
    return _module(report, section).get("data")


def _num(value: Any) -> str:
    return "—" if value is None else f"{value:g}" if isinstance(value, (int, float)) else str(value)


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_No rows._"]
    return (
        ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
        + ["| " + " | ".join(row) + " |" for row in rows]
    )


def _header(report: dict, emoji: bool) -> list[str]:
    meta = report.get("meta") or {}
    interp = report.get("interpretation") or {}
    target = f" · target `{meta.get('target')}`" if meta.get("target") else ""
    status = interp.get("overall_status", "ok")
    return [
        "# netcheck report",
        "",
        f"- Mode: `{meta.get('mode', 'auto')}`{target}",
        f"- Started: {meta.get('started_at', '?')} · finished: {meta.get('finished_at', '?')}",
        f"- Host OS: {meta.get('host_os', '?')} · run id `{meta.get('run_id', '?')}`",
        f"- Verdict: {badge(status, emoji)} **{status}** ({interp.get('overall_score', 0)}/100) — "
        f"{interp.get('summary_text', '')}",
        "",
    ]


def _findings(report: dict) -> list[dict]:
    return sorted(
        (report.get("interpretation") or {}).get("findings") or [],
        key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 9),
    )


def _tldr(report: dict, emoji: bool) -> list[str]:
    found = _findings(report)
    if not found:
        return ["## TL;DR", "", "No problems found on this connection.", ""]
    return ["## TL;DR", ""] + [
        f"- {badge(f.get('severity', 'info'), emoji)} **{f.get('title', '')}** — {f.get('detail', '')}"
        for f in found[:5]
    ] + [""]


_SECTION_TITLES = {
    "connection": "## Connection & identity",
    "ip_geo": "## Connection & identity",
    "vpn_assessment": "## VPN / proxy assessment",
    "bgp": "## ASN & BGP intelligence",
    "reputation": "## Reputation",
    "latency": "## Latency",
    "path": "## Path",
    "speed": "## Speed",
}


def unavailable(report: dict[str, Any], section: str) -> str | None:
    module = _module(report, section)
    if module.get("status") in ("ok", "partial") and module.get("data") is not None:
        return None
    detail = "; ".join(f"{e.get('source')}: {e.get('message')}" for e in module.get("errors") or [])
    if not detail:
        detail = "no data was collected for this section"
    return f"_Not available — {module.get('status', 'skipped')}: {detail}._"


def _connection(report: dict) -> list[str]:
    conn_note = unavailable(report, "connection")
    geo_note = unavailable(report, "ip_geo")
    if conn_note or geo_note:
        notes = [n for n in (conn_note, geo_note) if n]
        return [_SECTION_TITLES["connection"], "", *notes, ""]
    local = _data(report, "connection") or {}
    geo_bundle = _data(report, "ip_geo") or {}
    geo = geo_bundle.get("egress_v4") or {}
    v6 = geo_bundle.get("egress_v6") or {}
    cf = geo_bundle.get("cf_trace") or {}
    rows = [
        ["Interface", f"{local.get('iface_name') or '?'} (MTU {local.get('iface_mtu') or '?'})"],
        ["Local address", f"{local.get('local_ipv4') or '?'} / {local.get('local_ipv6') or '—'}"],
        ["Default gateway", local.get("default_gateway_v4") or "?"],
        ["Egress IPv4", f"{geo.get('ip') or '?'} ({geo.get('asn') or '?'} {geo.get('as_name') or geo.get('org') or ''})"],
        ["Egress IPv6", f"{v6.get('ip') or '—'} ({v6.get('asn') or '—'})"],
        ["Reverse DNS", geo.get("reverse_dns") or "—"],
        ["Location", f"{geo.get('city') or '?'}, {geo.get('country') or geo.get('country_code') or '?'}"],
        ["Address type", geo.get("ip_type") or "unknown"],
        ["Cloudflare colo", cf.get("colo") or "—"],
    ]
    lines = ["## Connection & identity", ""] + _table(["Field", "Value"], rows) + [""]
    if geo_bundle.get("dual_stack_note"):
        lines += [f"> {geo_bundle['dual_stack_note']}", ""]
    return lines


def _vpn(report: dict) -> list[str]:
    note = unavailable(report, "vpn_assessment")
    if note:
        return [_SECTION_TITLES["vpn_assessment"], "", note, ""]
    vpn = _data(report, "vpn_assessment") or {}
    lines = [
        "## VPN / proxy assessment",
        "",
        f"Verdict: **{vpn.get('verdict', 'unknown')}** · confidence {vpn.get('confidence', 0)}"
        f" · tunnel interface {vpn.get('tunnel_iface') or '—'}",
        "",
    ]
    lines += _table(
        ["Signal", "Observed", "Weight", "Direction", "Note"],
        [
            [
                s.get("name", ""),
                "yes" if s.get("observed") else "no",
                _num(s.get("weight")),
                s.get("direction", ""),
                s.get("note") or "—",
            ]
            for s in vpn.get("signals") or []
        ],
    )
    leak = vpn.get("dns_leak") or {}
    if leak:
        lines += ["", "### DNS leak", ""]
        lines += _table(
            ["Adapter", "Configured resolvers", "Echoed IP", "Echoed ASN", "Same ASN as egress"],
            [
                [
                    a.get("adapter", ""),
                    ", ".join(a.get("configured_resolvers") or []) or "—",
                    a.get("echoed_ip") or "—",
                    a.get("echoed_asn") or "—",
                    {True: "yes", False: "no", None: "?"}[a.get("matches_egress_asn")],
                ]
                for a in leak.get("per_adapter") or []
            ],
        )
        lines += ["", f"EDNS Client Subnet leaked: {'yes' if leak.get('ecs_leaked') else 'no'}", "", leak.get("note", "")]
    return lines + [""]


def _bgp(report: dict) -> list[str]:
    note = unavailable(report, "bgp")
    if note:
        return [_SECTION_TITLES["bgp"], "", note, ""]
    bgp = _data(report, "bgp") or {}
    rows = [
        ["ASN", f"{bgp.get('asn') or '?'} — {bgp.get('holder') or '?'}"],
        ["Registry", f"{bgp.get('registry') or '?'} (allocated {bgp.get('allocated_at') or '?'})"],
        ["Upstreams", ", ".join(bgp.get("upstreams") or []) or "—"],
        ["Peers", ", ".join(bgp.get("peers") or []) or "—"],
        ["Downstreams", ", ".join((bgp.get("downstreams") or [])[:10]) or "—"],
        ["Announced prefixes", f"{bgp.get('prefix_count_v4', 0)} IPv4 / {bgp.get('prefix_count_v6', 0)} IPv6"],
        ["Route stability", f"{bgp.get('stability', 'unknown')} ({len(bgp.get('flaps') or [])} updates in window)"],
        ["CAIDA ASRank", f"#{_num(bgp.get('asrank'))} · cone {_num(bgp.get('cone_asns'))} ASNs / "
                         f"{_num(bgp.get('cone_prefixes'))} prefixes"],
        ["PeeringDB", f"{bgp.get('pdb_info_type') or '—'} · {bgp.get('pdb_traffic') or '—'}"],
    ]
    lines = ["## ASN & BGP intelligence", ""] + _table(["Field", "Value"], rows)
    ixps = bgp.get("ixps") or []
    if ixps:
        lines += ["", "### IXP presence", ""]
        lines += _table(
            ["Exchange", "City", "Country", "Speed (Mbps)"],
            [[i.get("name", ""), i.get("city") or "—", i.get("country") or "—", _num(i.get("speed_mbps"))] for i in ixps],
        )
    return lines + [""]


def _reputation(report: dict) -> list[str]:
    note = unavailable(report, "reputation")
    if note:
        return [_SECTION_TITLES["reputation"], "", note, ""]
    rep = _data(report, "reputation") or {}
    idb = rep.get("internetdb") or {}
    rows = [
        ["FireHOL hits", ", ".join(rep.get("firehol_hits") or []) or "none"],
        ["Open ports (InternetDB)", ", ".join(str(p) for p in idb.get("ports") or []) or "none"],
        ["Tags", ", ".join(idb.get("tags") or []) or "none"],
        ["Known CVEs", ", ".join(idb.get("vulns") or []) or "none"],
        ["AbuseIPDB", _num(rep.get("abuseipdb_score")) if rep.get("abuseipdb_score") is not None else "not queried"],
    ]
    hits = rep.get("dnsbl_hits")
    if hits is None:
        rows.append(["DNSBL", "not run (pass --dnsbl)"])
    else:
        listed = ", ".join(h.get("zone", "") for h in hits) or "no listing"
        if rep.get("dnsbl_query_blocked"):
            listed += " · one or more zones answered with their query-error range, which is not a listing"
        rows.append(["DNSBL", listed])
    return (
        ["## Reputation", "", f"Captcha/blocklist risk: **{rep.get('captcha_risk', 'unknown')}** — "
                              f"{rep.get('rationale', '')}", ""]
        + _table(["Field", "Value"], rows)
        + [""]
    )


def _latency(report: dict) -> list[str]:
    note = unavailable(report, "latency")
    if note:
        return [_SECTION_TITLES["latency"], "", note, ""]
    pings = _data(report, "latency") or []
    lines = ["## Latency", ""] + _table(
        ["Host", "Address", "Method", "Avg ms", "Min", "Max", "Jitter", "Loss"],
        [
            [
                p.get("label", ""),
                p.get("host", ""),
                p.get("method", ""),
                _num(p.get("avg_ms")),
                _num(p.get("min_ms")),
                _num(p.get("max_ms")),
                _num(p.get("jitter_ms")),
                f"{p.get('loss_pct', 0)}%",
            ]
            for p in pings
        ],
    )
    if pings:
        lines += ["", "```"]
        lines += [f"{p.get('label', ''):<18}{sparkline(p.get('samples') or [])}" for p in pings]
        lines += ["```"]
    if any(p.get("method") == "tcp" for p in pings):
        lines += ["", "> Loss on a `tcp` row counts failed TCP connections, not dropped ICMP packets."]
    return lines + [""]


def _bar(value: Any) -> str:
    return "#" * int(min(float(value or 0.0), 200.0) / 10)


def _path(report: dict) -> list[str]:
    note = unavailable(report, "path")
    if note:
        return [_SECTION_TITLES["path"], "", note, ""]
    traces = _data(report, "path") or []
    lines = ["## Path", ""]
    for trace in traces:
        hops = trace.get("hops") or []
        jump = first_loss_jump(hops)
        lines += [
            f"### {trace.get('target') or '?'} — backend `{trace.get('backend', 'none')}`, "
            f"{'complete' if trace.get('completed') else 'incomplete'}",
            "",
            "```",
        ]
        for hop in hops:
            marker = " <<" if jump is not None and hop.get("ttl") == jump else ""
            lines.append(
                f"{hop.get('ttl', 0):>3}  {(hop.get('ip') or '*'):<39} "
                f"{_num(hop.get('avg_ms')):>8} ms  {hop.get('loss_pct', 0):>5}%  {_bar(hop.get('avg_ms'))}{marker}"
            )
        lines += ["```", ""]
    return lines


def _speed(report: dict) -> list[str]:
    note = unavailable(report, "speed")
    if note:
        return [_SECTION_TITLES["speed"], "", note, ""]
    speed = _data(report, "speed") or {}
    grade = speed.get("bufferbloat_grade") or "?"
    rows = [
        ["Method", speed.get("method", "none")],
        ["Server", speed.get("server") or "—"],
        ["Download", f"{_num(speed.get('download_mbps'))} Mbps"],
        ["Upload", f"{_num(speed.get('upload_mbps'))} Mbps"],
        ["Idle RTT", f"{_num(speed.get('idle_rtt_ms'))} ms"],
        ["Loaded RTT (down / up)", f"{_num(speed.get('loaded_rtt_down_ms'))} / {_num(speed.get('loaded_rtt_up_ms'))} ms"],
        ["Bufferbloat", f"grade {grade} — down +{_num(speed.get('bufferbloat_down_ms'))} ms, "
                        f"up +{_num(speed.get('bufferbloat_up_ms'))} ms"],
        ["Netflix OCA on-net", {True: "yes", False: "no", None: "—"}[speed.get("netflix_oca_onnet")]],
    ]
    lines = ["## Speed", ""] + _table(["Field", "Value"], rows) + ["", bufferbloat_consequence(grade)]
    attempts = speed.get("tier_attempts") or []
    if attempts:
        lines += ["", "### Cascade", ""]
        lines += _table(
            ["Tier", "Used", "Reason", "ms"],
            [
                [a.get("tier", ""), "yes" if a.get("ok") else "no", a.get("reason") or "—", _num(a.get("duration_ms"))]
                for a in attempts
            ],
        )
    return lines + [""]


def _problems(report: dict, emoji: bool) -> list[str]:
    found = _findings(report)
    if not found:
        return ["## Problems & recommendations", "", "Nothing to act on.", ""]
    lines = ["## Problems & recommendations", ""]
    for f in found:
        lines.append(f"- {badge(f.get('severity', 'info'), emoji)} **{f.get('title', '')}** — {f.get('detail', '')}")
        if f.get("advice"):
            lines.append(f"  - {f['advice']}")
    return lines + [""]


def _diagnostics(report: dict) -> list[str]:
    rows = []
    warnings: list[str] = []
    for section in SECTION_ORDER:
        module = _module(report, section)
        errors = "; ".join(f"{e.get('source')}: {e.get('kind')}" for e in module.get("errors") or []) or "—"
        rows.append([section, module.get("status", "skipped"), _num(module.get("duration_ms")), errors])
        warnings += list(module.get("warnings") or [])
    lines = ["## Run diagnostics", ""] + _table(["Module", "Status", "ms", "Errors"], rows)
    if warnings:
        lines += [""] + [f"- {w}" for w in warnings]
    return lines + [""]


def render_markdown(report: dict[str, Any], emoji: bool = True) -> str:
    lines = _header(report, emoji)
    lines += _tldr(report, emoji)
    lines += _connection(report)
    lines += _vpn(report)
    lines += _bgp(report)
    lines += _reputation(report)
    lines += _latency(report)
    lines += _path(report)
    lines += _speed(report)
    lines += _problems(report, emoji)
    lines += _diagnostics(report)
    return "\n".join(lines).rstrip() + "\n"
