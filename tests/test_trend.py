from __future__ import annotations

from netsleuth.trend import build_trend, render_trend, series_summary


def _report(started_at: str, avg_ms: float | None, download: float | None, score: int | None) -> dict:
    return {
        "meta": {"started_at": started_at},
        "latency": {"data": [{"label": "cloudflare-dns", "avg_ms": avg_ms}] if avg_ms is not None else []},
        "speed": {"data": {"download_mbps": download}},
        "interpretation": {"overall_score": score},
    }


def test_build_trend_over_a_single_report():
    trend = build_trend([_report("2026-01-01T00:00:00Z", 10.0, 100.0, 90)])
    assert trend.timestamps == ["2026-01-01T00:00:00Z"]
    assert trend.latency[0].label == "cloudflare-dns"
    assert trend.latency[0].values == [10.0]
    assert trend.download_mbps == [100.0]
    assert trend.overall_score == [90]


def test_build_trend_over_two_reports():
    reports = [
        _report("2026-01-01T00:00:00Z", 10.0, 100.0, 90),
        _report("2026-01-02T00:00:00Z", 12.0, 90.0, 85),
    ]
    trend = build_trend(reports)
    assert trend.latency[0].values == [10.0, 12.0]
    assert trend.download_mbps == [100.0, 90.0]


def test_build_trend_handles_a_hole_when_a_label_is_missing_from_one_report():
    reports = [
        _report("2026-01-01T00:00:00Z", 10.0, 100.0, 90),
        {"meta": {"started_at": "2026-01-02T00:00:00Z"}, "latency": {"data": []}, "speed": {"data": {}}, "interpretation": {}},
    ]
    trend = build_trend(reports)
    assert trend.latency[0].values == [10.0, None]


def test_build_trend_a_label_appearing_only_in_a_later_report():
    reports = [
        {"meta": {"started_at": "2026-01-01T00:00:00Z"}, "latency": {"data": []}, "speed": {"data": {}}, "interpretation": {}},
        _report("2026-01-02T00:00:00Z", 8.0, 100.0, 90),
    ]
    trend = build_trend(reports)
    assert trend.latency[0].values == [None, 8.0]


def test_series_summary_basic_stats():
    lo, median, hi, delta = series_summary([10.0, 20.0, 30.0])
    assert lo == 10.0
    assert median == 20.0
    assert hi == 30.0
    assert delta == 20.0


def test_series_summary_ignores_holes_for_min_max_median():
    lo, median, hi, delta = series_summary([None, 10.0, None, 30.0, None])
    assert lo == 10.0
    assert hi == 30.0
    assert delta == 20.0


def test_series_summary_all_none():
    assert series_summary([None, None]) == (None, None, None, None)


def test_render_trend_produces_readable_output():
    trend = build_trend([_report("2026-01-01T00:00:00Z", 10.0, 100.0, 90)])
    text = render_trend(trend)
    assert "Latency: cloudflare-dns" in text
    assert "Download" in text
    assert "Overall score" in text
