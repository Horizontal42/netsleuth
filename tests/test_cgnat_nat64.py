from __future__ import annotations

from netsleuth.config import Thresholds
from netsleuth.interpret import cgnat_findings, dual_stack_findings, path_findings
from netsleuth.ip_geo import nat64_prefix_from_aaaa
from netsleuth.models import LocalNet, TraceHop, TraceResult
from netsleuth.netinfo import is_cgnat


def test_is_cgnat_boundaries():
    assert is_cgnat("100.63.255.255") is False
    assert is_cgnat("100.64.0.0") is True
    assert is_cgnat("100.127.255.255") is True
    assert is_cgnat("100.128.0.0") is False
    assert is_cgnat(None) is False
    assert is_cgnat("not-an-ip") is False
    assert is_cgnat("2001:db8::1") is False


def test_nat64_prefix_from_aaaa_recognises_the_well_known_prefix():
    assert nat64_prefix_from_aaaa(["64:ff9b::c000:aa"]) == "64:ff9b::/96"


def test_nat64_prefix_from_aaaa_recognises_an_isp_specific_prefix():
    assert nat64_prefix_from_aaaa(["2001:db8:64::c000:ab"]) == "2001:db8:64::/96"


def test_nat64_prefix_from_aaaa_ignores_a_non_synthesized_answer():
    assert nat64_prefix_from_aaaa(["2606:4700:4700::1111"]) is None


def test_nat64_prefix_from_aaaa_handles_empty_and_garbage_input():
    assert nat64_prefix_from_aaaa([]) is None
    assert nat64_prefix_from_aaaa(["not-an-address"]) is None


def test_cgnat_findings_fires_on_local_ip_evidence():
    local = LocalNet(local_ipv4="100.64.5.5", cgnat=True, cgnat_evidence="local address 100.64.5.5 is in 100.64.0.0/10")
    findings = cgnat_findings(local, [])
    assert [f.id for f in findings] == ["net.cgnat"]
    assert findings[0].severity == "warn"


def test_cgnat_findings_fires_on_gateway_evidence():
    local = LocalNet(default_gateway_v4="100.70.0.1", cgnat=True, cgnat_evidence="default gateway 100.70.0.1 is in 100.64.0.0/10")
    assert [f.id for f in cgnat_findings(local, [])] == ["net.cgnat"]


def test_cgnat_findings_fires_on_traceroute_hop_evidence():
    local = LocalNet(local_ipv4="192.168.1.34", default_gateway_v4="192.168.1.1")
    trace = TraceResult(
        target="1.1.1.1",
        hops=[
            TraceHop(ttl=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.0),
            TraceHop(ttl=2, ip="100.65.1.1", loss_pct=0.0, avg_ms=8.0),
        ],
    )
    findings = cgnat_findings(local, [trace])
    assert [f.id for f in findings] == ["net.cgnat"]
    assert "hop 2" in findings[0].detail


def test_cgnat_findings_silent_on_a_clean_private_network():
    local = LocalNet(local_ipv4="192.168.1.34", default_gateway_v4="192.168.1.1")
    trace = TraceResult(target="1.1.1.1", hops=[TraceHop(ttl=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.0)])
    assert cgnat_findings(local, [trace]) == []


def test_dual_stack_findings_nat64_warns_on_a_v6_only_host():
    local = LocalNet(local_ipv6="2001:db8::1", is_dual_stack=False)
    findings = dual_stack_findings("2001:db8:64::/96", local)
    assert [f.id for f in findings] == ["net.nat64"]
    assert findings[0].severity == "warn"


def test_dual_stack_findings_nat64_is_informational_on_a_dual_stack_host():
    local = LocalNet(local_ipv4="203.0.113.5", local_ipv6="2001:db8::1", is_dual_stack=True)
    findings = dual_stack_findings("2001:db8:64::/96", local)
    assert findings[0].severity == "info"


def test_dual_stack_findings_silent_when_no_nat64_prefix():
    assert dual_stack_findings(None, LocalNet()) == []


def _trace(hop0: TraceHop) -> TraceResult:
    return TraceResult(target="1.1.1.1", resolved_ip="1.1.1.1", backend="icmplib", hops=[hop0], completed=True)


def test_path_findings_flags_loss_at_the_gateway_hop():
    local = LocalNet(default_gateway_v4="192.168.1.1")
    trace = _trace(TraceHop(ttl=1, ip="192.168.1.1", loss_pct=25.0, avg_ms=1.0))
    findings = path_findings(trace, local, Thresholds())
    ids = [f.id for f in findings]
    assert "path.first_hop_loss" in ids
    assert [f for f in findings if f.id == "path.first_hop_loss"][0].severity == "crit"
    assert "path.first_hop_unexpected" not in ids


def test_path_findings_flags_an_unexpected_first_hop():
    local = LocalNet(default_gateway_v4="192.168.1.1")
    trace = _trace(TraceHop(ttl=1, ip="10.0.0.1", loss_pct=0.0, avg_ms=1.0))
    findings = path_findings(trace, local, Thresholds())
    assert [f.id for f in findings] == ["path.first_hop_unexpected"]


def test_path_findings_without_local_param_is_unchanged():
    trace = _trace(TraceHop(ttl=1, ip="192.168.1.1", loss_pct=30.0, avg_ms=1.0))
    findings = path_findings(trace)
    assert all(not f.id.startswith("path.first_hop") for f in findings)


def test_path_findings_first_hop_empty_hops_still_reports_incomplete():
    trace = TraceResult(target="1.1.1.1", resolved_ip="1.1.1.1", backend="icmplib", hops=[], completed=False)
    assert [f.id for f in path_findings(trace, LocalNet())] == ["path.incomplete"]
