from __future__ import annotations

from netsleuth.interpret import ecmp_findings
from netsleuth.models import TraceHop, TraceResult
from netsleuth.probes.ecmp import detect_ecmp


def hop(ttl: int, ip: str | None, avg_ms: float | None = 10.0, asn: str | None = None) -> TraceHop:
    return TraceHop(ttl=ttl, ip=ip, avg_ms=avg_ms, asn=asn)


def trace(*hops: TraceHop, target: str = "1.1.1.1") -> TraceResult:
    return TraceResult(target=target, hops=list(hops))


def test_detect_ecmp_on_a_single_run_has_no_divergence():
    report = detect_ecmp([trace(hop(1, "192.168.1.1"), hop(2, "1.1.1.1"))])
    assert report.divergent_ttls == []
    assert report.runs == 1


def test_detect_ecmp_on_three_identical_runs_has_no_divergence():
    runs = [trace(hop(1, "192.168.1.1"), hop(2, "1.1.1.1")) for _ in range(3)]
    report = detect_ecmp(runs)
    assert report.divergent_ttls == []
    assert report.runs == 3


def test_detect_ecmp_flags_a_ttl_with_different_next_hops():
    runs = [
        trace(hop(1, "192.168.1.1"), hop(2, "10.0.0.1")),
        trace(hop(1, "192.168.1.1"), hop(2, "10.0.0.2")),
        trace(hop(1, "192.168.1.1"), hop(2, "10.0.0.1")),
    ]
    report = detect_ecmp(runs)
    assert report.divergent_ttls == [2]
    hop2 = next(h for h in report.hops if h.ttl == 2)
    assert set(hop2.ips) == {"10.0.0.1", "10.0.0.2"}


def test_detect_ecmp_computes_a_large_rtt_gap_between_branches():
    runs = [
        trace(hop(1, "10.0.0.1", avg_ms=10.0)),
        trace(hop(1, "10.0.0.2", avg_ms=80.0)),
    ]
    report = detect_ecmp(runs)
    hop1 = report.hops[0]
    assert hop1.rtt_spread_ms == 70.0


def test_detect_ecmp_handles_runs_of_differing_length():
    runs = [
        trace(hop(1, "10.0.0.1"), hop(2, "1.1.1.1")),
        trace(hop(1, "10.0.0.1")),
    ]
    report = detect_ecmp(runs)
    assert report.divergent_ttls == []
    assert {h.ttl for h in report.hops} == {1, 2}


def test_detect_ecmp_excludes_none_ip_hops():
    runs = [
        trace(hop(1, "10.0.0.1")),
        trace(hop(1, None)),
    ]
    report = detect_ecmp(runs)
    assert report.hops[0].ips == ["10.0.0.1"]
    assert report.divergent_ttls == []


def test_detect_ecmp_on_no_runs():
    report = detect_ecmp([])
    assert report.hops == []
    assert report.runs == 0


def test_ecmp_findings_silent_when_no_divergence():
    report = detect_ecmp([trace(hop(1, "10.0.0.1"))])
    assert ecmp_findings(report) == []


def test_ecmp_findings_info_when_divergent_but_close_in_rtt():
    runs = [
        trace(hop(1, "10.0.0.1", avg_ms=10.0)),
        trace(hop(1, "10.0.0.2", avg_ms=12.0)),
    ]
    report = detect_ecmp(runs)
    findings = ecmp_findings(report)
    assert [f.id for f in findings] == [f"path.ecmp.{report.target}"]
    assert findings[0].severity == "info"


def test_ecmp_findings_warns_on_asymmetric_branches():
    runs = [
        trace(hop(1, "10.0.0.1", avg_ms=10.0)),
        trace(hop(1, "10.0.0.2", avg_ms=80.0)),
    ]
    report = detect_ecmp(runs)
    findings = ecmp_findings(report)
    ids = [f.id for f in findings]
    assert f"path.ecmp.{report.target}" in ids
    assert f"path.ecmp_asymmetric.{report.target}" in ids
    asymmetric = [f for f in findings if f.id.startswith("path.ecmp_asymmetric")][0]
    assert asymmetric.severity == "warn"
