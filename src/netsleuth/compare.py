from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netsleuth.exporter import badge


@dataclass
class Change:
    """A single metric change between two reports.

    Attributes:
        label: Human-readable description of what changed.
        before: Value before the change.
        after: Value after the change.
        delta: Numeric difference (after - before), or None if not applicable.
    """

    label: str
    before: Any = None
    after: Any = None
    delta: float | None = None


@dataclass
class ReportDiff:
    """Collection of changes between two network diagnostic reports.

    Attributes:
        identity: Changes in network identity (IP, ASN, country, etc.).
        latency: Changes in latency metrics for reference hosts.
        speed: Changes in speedtest results.
        new_findings: Findings present in the newer report but not the older.
        resolved_findings: Findings present in the older report but cleared in the newer.
    """

    identity: list[Change] = field(default_factory=list)
    latency: list[Change] = field(default_factory=list)
    speed: list[Change] = field(default_factory=list)
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)


def load_report(path: Path) -> dict:
    """Load a JSON report from disk.

    Args:
        path: Path to the JSON report file.

    Returns:
        Parsed report dictionary.

    Raises:
        FileNotFoundError: If the report file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _data(report: dict, section: str) -> Any:
    return (report.get(section) or {}).get("data")


def _geo(report: dict) -> dict:
    bundle = _data(report, "ip_geo") or {}
    return (bundle.get("egress_v4") or {}) if isinstance(bundle, dict) else {}


def _delta(before: Any, after: Any) -> float | None:
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        return round(float(after) - float(before), 3)
    return None


def identity_changes(before: dict, after: dict) -> list[Change]:
    a, b = _geo(before), _geo(after)
    vpn_a = _data(before, "vpn_assessment") or {}
    vpn_b = _data(after, "vpn_assessment") or {}
    pairs = [
        ("Egress IP", a.get("ip"), b.get("ip")),
        ("ASN", a.get("asn"), b.get("asn")),
        ("Organisation", a.get("as_name") or a.get("org"), b.get("as_name") or b.get("org")),
        ("Country", a.get("country_code"), b.get("country_code")),
        ("Address type", a.get("ip_type"), b.get("ip_type")),
        ("VPN verdict", vpn_a.get("verdict"), vpn_b.get("verdict")),
        ("VPN confidence", vpn_a.get("confidence"), vpn_b.get("confidence")),
    ]
    return [Change(label, x, y, _delta(x, y)) for label, x, y in pairs if x != y]


def latency_changes(before: dict, after: dict) -> list[Change]:
    a = {p.get("label"): p for p in _data(before, "latency") or []}
    b = {p.get("label"): p for p in _data(after, "latency") or []}
    changes: list[Change] = []
    for label in sorted(set(a) | set(b)):
        pa, pb = a.get(label) or {}, b.get(label) or {}
        for metric in ("avg_ms", "jitter_ms", "loss_pct"):
            x, y = pa.get(metric), pb.get(metric)
            if x != y:
                changes.append(Change(f"{label} {metric}", x, y, _delta(x, y)))
    return changes


def speed_changes(before: dict, after: dict) -> list[Change]:
    a, b = _data(before, "speed") or {}, _data(after, "speed") or {}
    fields = (
        ("Speedtest method", "method"),
        ("Download Mbps", "download_mbps"),
        ("Upload Mbps", "upload_mbps"),
        ("Bufferbloat down ms", "bufferbloat_down_ms"),
        ("Bufferbloat up ms", "bufferbloat_up_ms"),
        ("Bufferbloat grade", "bufferbloat_grade"),
    )
    return [
        Change(label, a.get(key), b.get(key), _delta(a.get(key), b.get(key)))
        for label, key in fields
        if a.get(key) != b.get(key)
    ]


def finding_changes(before: dict, after: dict) -> tuple[list[dict], list[dict]]:
    a = {f.get("id"): f for f in (before.get("interpretation") or {}).get("findings") or []}
    b = {f.get("id"): f for f in (after.get("interpretation") or {}).get("findings") or []}
    return [b[i] for i in b if i not in a], [a[i] for i in a if i not in b]


def diff_reports(before: dict, after: dict) -> ReportDiff:
    new, resolved = finding_changes(before, after)
    return ReportDiff(
        identity=identity_changes(before, after),
        latency=latency_changes(before, after),
        speed=speed_changes(before, after),
        new_findings=new,
        resolved_findings=resolved,
    )


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    return f"{value:g}" if isinstance(value, (int, float)) else str(value)


def _block(title: str, changes: list[Change]) -> list[str]:
    if not changes:
        return [f"### {title}", "", "No change.", ""]
    return (
        [f"### {title}", "", "| Field | Before | After | Delta |", "|---|---|---|---|"]
        + [f"| {c.label} | {_fmt(c.before)} | {_fmt(c.after)} | {_fmt(c.delta)} |" for c in changes]
        + [""]
    )


def render_diff(diff: ReportDiff, emoji: bool = True) -> str:
    lines = ["# netsleuth compare", ""]
    lines += _block("Identity", diff.identity)
    lines += _block("Latency", diff.latency)
    lines += _block("Speed", diff.speed)
    lines += ["### Findings", ""]
    if not diff.new_findings and not diff.resolved_findings:
        lines += ["No findings appeared or cleared.", ""]
    else:
        lines += [
            f"- new: {badge(f.get('severity', 'info'), emoji)} {f.get('title', '')}" for f in diff.new_findings
        ]
        lines += [f"- resolved: {badge('ok', emoji)} {f.get('title', '')}" for f in diff.resolved_findings]
        lines += [""]
    return "\n".join(lines).rstrip() + "\n"
