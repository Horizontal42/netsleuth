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


from netcheck.config import VpnBands
from netcheck.models import AdapterLeakResult, CfTrace, DnsLeak, IpGeo, LocalNet, Signal
from netcheck.interpret import SIGNAL_WEIGHTS, assess_vpn, gather_vpn_signals, score_vpn


def sig(name: str, observed: bool = True) -> Signal:
    return Signal(name=name, observed=observed, weight=SIGNAL_WEIGHTS[name], direction="vpn")


def test_no_signals_means_no_vpn():
    verdict, confidence = score_vpn([], VpnBands())
    assert verdict == "none"
    assert confidence == 0.0


def test_unobserved_signals_contribute_nothing():
    verdict, confidence = score_vpn(
        [sig("tunnel_iface", observed=False), sig("cf_warp", observed=False)], VpnBands()
    )
    assert verdict == "none"
    assert confidence == 0.0


def test_cloudflare_warp_alone_is_enough_for_likely():
    verdict, confidence = score_vpn([sig("cf_warp")], VpnBands())
    assert verdict == "likely"
    assert confidence == pytest.approx(0.50)


def test_tunnel_interface_plus_hosting_egress_is_confirmed():
    verdict, confidence = score_vpn([sig("tunnel_iface"), sig("provider_hosting")], VpnBands())
    assert verdict == "confirmed"
    assert confidence >= 0.75


def test_a_mobile_flag_with_a_timezone_mismatch_does_not_fire():
    # This combination is normal for anyone travelling on a phone hotspot and
    # must not be reported as a VPN.
    verdict, confidence = score_vpn([sig("provider_mobile"), sig("timezone_mismatch")], VpnBands())
    assert verdict == "none"
    assert confidence < 0.40


def test_mtu_anomaly_alone_does_not_fire():
    verdict, _ = score_vpn([sig("mtu_anomaly")], VpnBands())
    assert verdict == "none"


def test_dns_asn_mismatch_alone_does_not_fire():
    verdict, _ = score_vpn([sig("dns_asn_mismatch")], VpnBands())
    assert verdict == "none"


def test_mtu_anomaly_plus_tunnel_iface_plus_dns_mismatch_is_confirmed():
    verdict, confidence = score_vpn(
        [sig("tunnel_iface"), sig("mtu_anomaly"), sig("dns_asn_mismatch")], VpnBands()
    )
    assert verdict == "confirmed"
    assert confidence == pytest.approx(0.80)


def test_confidence_is_capped_at_one():
    _, confidence = score_vpn([sig(name) for name in SIGNAL_WEIGHTS], VpnBands())
    assert confidence == 1.0


def test_clean_direction_signals_reduce_confidence():
    signals = [
        sig("provider_hosting"),
        Signal(name="pdb_eyeball_isp", observed=True, weight=0.2, direction="clean"),
    ]
    _, confidence = score_vpn(signals, VpnBands())
    assert confidence == pytest.approx(0.20)


def test_gather_signals_flags_a_wireguard_tunnel_with_a_hosting_egress():
    local = LocalNet(iface_name="wg0", local_ipv4="10.7.0.2", iface_mtu=1420, default_gateway_v4="10.7.0.1")
    geo = IpGeo(ip="203.0.113.44", asn="AS64500", country_code="NL", timezone="Europe/Amsterdam")
    signals = {s.name: s for s in gather_vpn_signals(
        local=local,
        geo=geo,
        cf=CfTrace(ip="203.0.113.44", warp="off"),
        dns_leak=None,
        pdb_info_type="NSP",
        os_timezone="Europe/Amsterdam",
        provider_flags={"hosting": True, "proxy": False, "mobile": False},
    )}
    assert signals["tunnel_iface"].observed is True
    assert signals["tunnel_iface"].note == "wg0"
    assert signals["mtu_anomaly"].observed is True
    assert signals["mtu_anomaly"].note == "wireguard"
    assert signals["provider_hosting"].observed is True
    assert signals["cf_warp"].observed is False
    assert signals["timezone_mismatch"].observed is False


def test_gather_signals_detects_a_dns_resolver_in_another_asn():
    leak = DnsLeak(
        per_adapter=[
            AdapterLeakResult(
                adapter="Wi-Fi",
                configured_resolvers=["192.168.1.1"],
                echoed_ip="203.0.113.9",
                echoed_asn="AS64501",
                matches_egress_asn=False,
            )
        ]
    )
    signals = {s.name: s for s in gather_vpn_signals(
        local=LocalNet(iface_name="eth0"),
        geo=IpGeo(asn="AS64500"),
        cf=None,
        dns_leak=leak,
        pdb_info_type=None,
        os_timezone=None,
        provider_flags={},
    )}
    assert signals["dns_asn_mismatch"].observed is True
    assert "Wi-Fi" in signals["dns_asn_mismatch"].note


def test_gather_signals_detects_cloudflare_warp():
    signals = {s.name: s for s in gather_vpn_signals(
        local=LocalNet(),
        geo=IpGeo(),
        cf=CfTrace(warp="on"),
        dns_leak=None,
        pdb_info_type=None,
        os_timezone=None,
        provider_flags={},
    )}
    assert signals["cf_warp"].observed is True


def test_assess_vpn_returns_a_complete_assessment():
    assessment = assess_vpn(
        signals=[sig("tunnel_iface"), sig("provider_hosting")],
        bands=VpnBands(),
        tunnel_iface="wg0",
        dns_leak=None,
    )
    assert assessment.verdict == "confirmed"
    assert assessment.tunnel_iface == "wg0"
    assert len(assessment.signals) == 2
    assert assessment.confidence >= 0.75
