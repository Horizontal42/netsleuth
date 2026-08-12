from __future__ import annotations

from dataclasses import dataclass, field

from netsleuth.exporter import sparkline
from netsleuth.stats import percentile


@dataclass
class TrendSeries:
    label: str
    values: list[float | None] = field(default_factory=list)


@dataclass
class Trend:
    timestamps: list[str] = field(default_factory=list)
    latency: list[TrendSeries] = field(default_factory=list)
    download_mbps: list[float | None] = field(default_factory=list)
    upload_mbps: list[float | None] = field(default_factory=list)
    overall_score: list[float | None] = field(default_factory=list)


def build_trend(reports: list[dict]) -> Trend:
    """`reports` must be chronologically ordered, oldest first."""
    timestamps = [(r.get("meta") or {}).get("started_at") or "" for r in reports]

    labels: list[str] = []
    for r in reports:
        for p in (r.get("latency") or {}).get("data") or []:
            label = p.get("label") or ""
            if label not in labels:
                labels.append(label)
    latency_by_label: dict[str, list[float | None]] = {label: [None] * len(reports) for label in labels}

    download_mbps: list[float | None] = []
    upload_mbps: list[float | None] = []
    overall_score: list[float | None] = []
    for i, r in enumerate(reports):
        by_label = {p.get("label"): p for p in (r.get("latency") or {}).get("data") or []}
        for label in labels:
            p = by_label.get(label)
            latency_by_label[label][i] = p.get("avg_ms") if p else None
        speed = (r.get("speed") or {}).get("data") or {}
        download_mbps.append(speed.get("download_mbps"))
        upload_mbps.append(speed.get("upload_mbps"))
        overall_score.append((r.get("interpretation") or {}).get("overall_score"))

    return Trend(
        timestamps=timestamps,
        latency=[TrendSeries(label, latency_by_label[label]) for label in labels],
        download_mbps=download_mbps,
        upload_mbps=upload_mbps,
        overall_score=overall_score,
    )


def series_summary(values: list[float | None]) -> tuple[float | None, float | None, float | None, float | None]:
    """Returns (min, median, max, delta first->last), ignoring holes."""
    numbers = [v for v in values if v is not None]
    if not numbers:
        return None, None, None, None
    first = next((v for v in values if v is not None), None)
    last = next((v for v in reversed(values) if v is not None), None)
    delta = None if first is None or last is None else round(last - first, 3)
    return min(numbers), round(percentile(numbers, 50.0), 3), max(numbers), delta


def _fmt(value: float | None) -> str:
    return "—" if value is None else f"{value:g}"


def _summary_line(values: list[float | None], unit: str) -> str:
    lo, median, hi, delta = series_summary(values)
    delta_str = _fmt(delta)
    if delta is not None and delta > 0:
        delta_str = f"+{delta_str}"
    return f"{sparkline(values)}  min={_fmt(lo)} median={_fmt(median)} max={_fmt(hi)} first→last={delta_str} {unit}"


def render_trend(trend: Trend, emoji: bool = True) -> str:
    lines = ["# netsleuth trend", "", f"Runs: {len(trend.timestamps)}"]
    if trend.timestamps:
        lines.append(f"From {trend.timestamps[0]} to {trend.timestamps[-1]}")
    lines.append("")
    for series in trend.latency:
        lines += [f"### Latency: {series.label}", _summary_line(series.values, "ms"), ""]
    lines += ["### Download", _summary_line(trend.download_mbps, "Mbps"), ""]
    lines += ["### Upload", _summary_line(trend.upload_mbps, "Mbps"), ""]
    lines += ["### Overall score", _summary_line(trend.overall_score, "/100"), ""]
    return "\n".join(lines).rstrip() + "\n"
