from __future__ import annotations

from netsleuth.metrics import Metric, collect_metrics, render_csv, render_prometheus


def _report(**overrides) -> dict:
    base = {
        "meta": {"run_id": "abc123"},
        "ip_geo": {"status": "ok", "data": {"egress_v4": {"asn": "AS64500", "country_code": "RU"}}},
        "latency": {
            "status": "ok",
            "data": [
                {"label": "cloudflare-dns", "host": "1.1.1.1", "method": "icmp_win", "avg_ms": 10.0, "loss_pct": 0.0}
            ],
        },
        "speed": {"status": "ok", "data": {"download_mbps": 100.0, "upload_mbps": None}},
        "tls": {"status": "skipped", "data": None},
        "path": {"status": "ok", "data": []},
        "prefix_benchmark": {"status": "skipped", "data": None},
        "bgp": {"status": "skipped", "data": None},
        "vpn_assessment": {"status": "ok", "data": {"confidence": 0.1}},
        "reputation": {"status": "skipped", "data": None},
        "interpretation": {"overall_score": 90, "findings": [{"severity": "warn"}, {"severity": "warn"}]},
    }
    base.update(overrides)
    return base


def test_collect_metrics_extracts_latency_and_skips_none_fields():
    metrics = collect_metrics(_report())
    latency_avg = [m for m in metrics if m.name == "netsleuth_latency_avg_ms"]
    assert len(latency_avg) == 1
    assert latency_avg[0].value == 10.0
    assert latency_avg[0].labels == {"label": "cloudflare-dns", "host": "1.1.1.1", "method": "icmp_win"}
    # upload_mbps is None -> no metric emitted
    assert not [m for m in metrics if m.name == "netsleuth_speed_upload_mbps"]


def test_collect_metrics_a_skipped_section_contributes_nothing():
    metrics = collect_metrics(_report())
    assert not [m for m in metrics if m.name.startswith("netsleuth_tls_")]
    assert not [m for m in metrics if m.name.startswith("netsleuth_bgp_")]


def test_collect_metrics_always_emits_up_and_run_info():
    metrics = collect_metrics(_report())
    up = [m for m in metrics if m.name == "netsleuth_up"]
    assert up == [Metric("netsleuth_up", 1.0)]
    run_info = [m for m in metrics if m.name == "netsleuth_run_info"]
    assert run_info[0].labels == {"asn": "AS64500", "country": "RU", "run_id": "abc123"}


def test_collect_metrics_aggregates_findings_by_severity():
    metrics = collect_metrics(_report())
    findings = {m.labels["severity"]: m.value for m in metrics if m.name == "netsleuth_findings_total"}
    assert findings == {"warn": 2.0}


def test_render_prometheus_has_one_help_and_type_per_family():
    metrics = [
        Metric("netsleuth_latency_avg_ms", 10.0, {"label": "a"}),
        Metric("netsleuth_latency_avg_ms", 20.0, {"label": "b"}),
    ]
    text = render_prometheus(metrics)
    assert text.count("# HELP netsleuth_latency_avg_ms") == 1
    assert text.count("# TYPE netsleuth_latency_avg_ms") == 1
    assert 'netsleuth_latency_avg_ms{label="a"} 10' in text
    assert 'netsleuth_latency_avg_ms{label="b"} 20' in text


def test_render_prometheus_handles_no_labels():
    text = render_prometheus([Metric("netsleuth_up", 1.0)])
    assert "netsleuth_up 1" in text


def test_render_prometheus_escapes_special_characters_in_labels():
    text = render_prometheus([Metric("netsleuth_x", 1.0, {"host": 'weird"name\\here'})])
    assert 'host="weird\\"name\\\\here"' in text


def test_render_csv_has_a_header_row_and_quotes_a_comma_in_a_label():
    metrics = [Metric("netsleuth_x", 5.0, {"target": "a, b"})]
    text = render_csv(metrics)
    lines = text.strip().splitlines()
    assert lines[0] == "metric,labels,value"
    assert '"target=a, b"' in lines[1]
