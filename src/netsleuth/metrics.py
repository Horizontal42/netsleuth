from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Metric:
    name: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)


def _data(report: dict, section: str) -> Any:
    return (report.get(section) or {}).get("data")


def _add(metrics: list[Metric], name: str, value: Any, labels: dict[str, str] | None = None) -> None:
    if value is None:
        return
    try:
        metrics.append(Metric(name, float(value), labels or {}))
    except (TypeError, ValueError):
        return


def collect_metrics(report: dict) -> list[Metric]:
    metrics: list[Metric] = []
    meta = report.get("meta") or {}
    metrics.append(Metric("netsleuth_up", 1.0))

    geo = (_data(report, "ip_geo") or {}).get("egress_v4") or {}
    metrics.append(
        Metric(
            "netsleuth_run_info",
            1.0,
            {
                "asn": geo.get("asn") or "",
                "country": geo.get("country_code") or "",
                "run_id": meta.get("run_id") or "",
            },
        )
    )

    for p in _data(report, "latency") or []:
        labels = {"label": p.get("label") or "", "host": p.get("host") or "", "method": p.get("method") or ""}
        for metric_name in ("avg_ms", "min_ms", "max_ms", "jitter_ms", "loss_pct", "p95_ms", "p99_ms"):
            _add(metrics, f"netsleuth_latency_{metric_name}", p.get(metric_name), labels)

    speed = _data(report, "speed") or {}
    for metric_name in (
        "download_mbps",
        "upload_mbps",
        "idle_rtt_ms",
        "loaded_rtt_down_ms",
        "loaded_rtt_up_ms",
        "bufferbloat_down_ms",
        "bufferbloat_up_ms",
    ):
        _add(metrics, f"netsleuth_speed_{metric_name}", speed.get(metric_name))

    for r in _data(report, "tls") or []:
        labels = {"label": r.get("label") or "", "host": r.get("host") or ""}
        _add(metrics, "netsleuth_tls_tcp_rtt_ms", r.get("tcp_rtt_ms"), labels)
        _add(metrics, "netsleuth_tls_handshake_ms", r.get("tls_handshake_ms"), labels)
        _add(metrics, "netsleuth_tls_ttfb_ms", r.get("ttfb_ms"), labels)

    for trace in _data(report, "path") or []:
        target = trace.get("target") or ""
        for hop in trace.get("hops") or []:
            labels = {
                "target": target,
                "ttl": str(hop.get("ttl", "")),
                "ip": hop.get("ip") or "",
                "asn": hop.get("asn") or "",
            }
            _add(metrics, "netsleuth_path_hop_avg_ms", hop.get("avg_ms"), labels)
            _add(metrics, "netsleuth_path_hop_loss_pct", hop.get("loss_pct"), labels)

    bench = _data(report, "prefix_benchmark") or {}
    for p in bench.get("results") or []:
        labels = {"prefix": p.get("prefix") or ""}
        _add(metrics, "netsleuth_prefix_avg_ms", p.get("avg_ms"), labels)
        _add(metrics, "netsleuth_prefix_loss_pct", p.get("loss_pct"), labels)
    _add(metrics, "netsleuth_prefix_spread_ms", bench.get("spread_ms"))

    bgp = _data(report, "bgp") or {}
    _add(metrics, "netsleuth_bgp_prefix_count", bgp.get("prefix_count_v4"), {"family": "4"})
    _add(metrics, "netsleuth_bgp_prefix_count", bgp.get("prefix_count_v6"), {"family": "6"})
    _add(metrics, "netsleuth_bgp_asrank", bgp.get("asrank"))
    _add(metrics, "netsleuth_bgp_cone_asns", bgp.get("cone_asns"))
    _add(metrics, "netsleuth_bgp_cone_prefixes", bgp.get("cone_prefixes"))

    vpn = _data(report, "vpn_assessment") or {}
    _add(metrics, "netsleuth_vpn_confidence", vpn.get("confidence"))

    reputation = _data(report, "reputation") or {}
    _add(metrics, "netsleuth_reputation_abuseipdb_score", reputation.get("abuseipdb_score"))

    interpretation = report.get("interpretation") or {}
    _add(metrics, "netsleuth_overall_score", interpretation.get("overall_score"))

    severity_counts: dict[str, int] = {}
    for finding in interpretation.get("findings") or []:
        severity = finding.get("severity") or "info"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    for severity, count in severity_counts.items():
        metrics.append(Metric("netsleuth_findings_total", float(count), {"severity": severity}))

    return metrics


_ESCAPE_MAP = {"\\": "\\\\", '"': '\\"', "\n": "\\n"}


def _escape_label(value: str) -> str:
    return "".join(_ESCAPE_MAP.get(ch, ch) for ch in value)


def _format_value(value: float) -> str:
    return str(int(value)) if value == int(value) else repr(value)


def render_prometheus(metrics: list[Metric]) -> str:
    order: list[str] = []
    by_name: dict[str, list[Metric]] = {}
    for m in metrics:
        if m.name not in by_name:
            by_name[m.name] = []
            order.append(m.name)
        by_name[m.name].append(m)

    lines: list[str] = []
    for name in order:
        lines.append(f"# HELP {name} netsleuth metric")
        lines.append(f"# TYPE {name} gauge")
        for m in by_name[name]:
            if m.labels:
                label_str = ",".join(f'{k}="{_escape_label(str(v))}"' for k, v in m.labels.items())
                lines.append(f"{name}{{{label_str}}} {_format_value(m.value)}")
            else:
                lines.append(f"{name} {_format_value(m.value)}")
    return "\n".join(lines) + "\n"


def render_csv(metrics: list[Metric]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["metric", "labels", "value"])
    for m in metrics:
        label_str = ";".join(f"{k}={v}" for k, v in m.labels.items())
        writer.writerow([m.name, label_str, _format_value(m.value)])
    return buf.getvalue()
