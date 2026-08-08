from __future__ import annotations

import pytest

from netcheck.config import Band, Thresholds
from netcheck.models import PingResult, TraceHop, TraceResult
from netcheck.interpret import latency_findings, path_findings, severity_for, worst


@pytest.fixture()
def thresholds() -> Thresholds:
    return Thresholds()


def test_severity_bands_are_inclusive_at_the_good_edge():
    band = Band(good=40.0, warn=100.0)
    assert severity_for(10.0, band) == "ok"
    assert severity_for(40.0, band) == "ok"
    assert severity_for(40.1, band) == "warn"
    assert severity_for(100.0, band) == "warn"
    assert severity_for(100.1, band) == "crit"


def test_severity_of_a_missing_value_is_info_not_ok():
    assert severity_for(None, Band(good=40.0, warn=100.0)) == "info"


def test_severity_can_be_inverted_for_metrics_where_higher_is_better():
    band = Band(good=50.0, warn=10.0)
    assert severity_for(100.0, band, higher_is_worse=False) == "ok"
    assert severity_for(50.0, band, higher_is_worse=False) == "ok"
    assert severity_for(30.0, band, higher_is_worse=False) == "warn"
    assert severity_for(5.0, band, higher_is_worse=False) == "crit"


def test_worst_picks_the_highest_severity():
    assert worst(["ok", "info", "warn"]) == "warn"
    assert worst(["ok", "crit", "warn"]) == "crit"
    assert worst([]) == "ok"
    assert worst(["ok", "ok"]) == "ok"


def ping(**kw) -> PingResult:
    base = dict(
        label="cloudflare-dns",
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_dgram",
        sent=20,
        received=20,
        loss_pct=0.0,
        min_ms=10.0,
        avg_ms=12.0,
        max_ms=15.0,
        mdev_ms=1.0,
        jitter_ms=1.0,
        samples=[],
    )
    base.update(kw)
    return PingResult(**base)


def test_a_healthy_ping_produces_no_findings(thresholds):
    assert latency_findings([ping()], thresholds) == []


def test_high_latency_produces_a_warn_finding_with_metric_and_threshold(thresholds):
    findings = latency_findings([ping(avg_ms=130.0)], thresholds)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "latency.avg.cloudflare-dns"
    assert f.severity == "crit"
    assert f.metric == "avg_ms"
    assert f.value == 130.0
    assert f.threshold == 100.0
    assert f.advice


def test_high_jitter_and_loss_each_produce_their_own_finding(thresholds):
    findings = latency_findings([ping(jitter_ms=25.0, loss_pct=5.0, received=19)], thresholds)
    ids = sorted(f.id for f in findings)
    assert ids == ["latency.jitter.cloudflare-dns", "latency.loss.cloudflare-dns"]


def test_tcp_measured_loss_is_labelled_as_connection_failures_not_packet_loss(thresholds):
    findings = latency_findings([ping(method="tcp", loss_pct=10.0)], thresholds)
    loss = [f for f in findings if f.id.startswith("latency.loss")][0]
    assert "connection failure" in loss.detail.lower()
    assert "packet loss" not in loss.detail.lower()


def test_a_fully_dead_host_is_critical_regardless_of_bands(thresholds):
    findings = latency_findings(
        [ping(received=0, loss_pct=100.0, avg_ms=None, min_ms=None, max_ms=None, jitter_ms=None)],
        thresholds,
    )
    assert [f.severity for f in findings] == ["crit"]
    assert findings[0].id == "latency.unreachable.cloudflare-dns"


def test_path_findings_highlight_the_first_sustained_loss_jump():
    trace = TraceResult(
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        backend="mtr_json",
        hops=[
            TraceHop(ttl=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.0),
            TraceHop(ttl=2, ip="10.64.0.1", loss_pct=0.0, avg_ms=9.0),
            TraceHop(ttl=3, ip="198.51.100.7", loss_pct=60.0, avg_ms=40.0),
            TraceHop(ttl=4, ip="1.1.1.1", loss_pct=55.0, avg_ms=41.0),
        ],
        completed=True,
    )
    findings = path_findings(trace)
    loss = [f for f in findings if f.id == "path.loss_jump"][0]
    assert loss.severity == "crit"
    assert "hop 3" in loss.detail
    assert "198.51.100.7" in loss.detail


def test_path_findings_ignore_a_single_hop_that_rate_limits_icmp():
    trace = TraceResult(
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        backend="mtr_json",
        hops=[
            TraceHop(ttl=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.0),
            TraceHop(ttl=2, ip="10.64.0.1", loss_pct=100.0, avg_ms=None),
            TraceHop(ttl=3, ip="1.1.1.1", loss_pct=0.0, avg_ms=12.0),
        ],
        completed=True,
    )
    assert [f.id for f in path_findings(trace)] == []


def test_path_findings_report_an_incomplete_trace():
    trace = TraceResult(target="1.1.1.1", resolved_ip="1.1.1.1", backend="icmplib", hops=[], completed=False)
    assert [f.id for f in path_findings(trace)] == ["path.incomplete"]
