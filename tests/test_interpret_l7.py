from __future__ import annotations

import re

import pytest

from netsleuth.config import Thresholds
from netsleuth.interpret import (
    dns_advanced_findings,
    dpi_findings,
    path_diversity_findings,
    prefix_findings,
    tls_findings,
)
from netsleuth.models import (
    AnycastHop,
    DnsAdvanced,
    DpiCheckResult,
    PathDiversity,
    PortProbe,
    PrefixBenchmark,
    PrefixProbe,
    ResolverProbe,
    TlsResult,
)

_CYRILLIC = re.compile(r"[а-яА-ЯёЁ]")


def has_cyrillic(text: str) -> bool:
    return bool(_CYRILLIC.search(text))


@pytest.fixture()
def thresholds() -> Thresholds:
    return Thresholds()


def tls(**kw) -> TlsResult:
    base = dict(label="cloudflare", host="cloudflare.com", port=443, tcp_rtt_ms=20.0, tls_handshake_ms=25.0, ttfb_ms=50.0)
    base.update(kw)
    return TlsResult(**base)


def test_healthy_tls_result_produces_no_findings(thresholds):
    assert tls_findings([tls()], thresholds) == []


def test_tls_error_produces_a_labeled_unreachable_finding(thresholds):
    findings = tls_findings([tls(tcp_rtt_ms=None, tls_handshake_ms=None, ttfb_ms=None, error="timeout")], thresholds)
    assert len(findings) == 1
    assert findings[0].id == "tls.unreachable.cloudflare"
    assert findings[0].severity == "warn"
    assert has_cyrillic(findings[0].title_ru)
    assert has_cyrillic(findings[0].detail_ru)


def test_slow_handshake_above_threshold_produces_a_warn_finding(thresholds):
    findings = tls_findings([tls(tls_handshake_ms=350.0)], thresholds)
    ids = [f.id for f in findings]
    assert "tls.handshake_slow.cloudflare" in ids


def test_fast_handshake_below_threshold_produces_no_handshake_finding(thresholds):
    findings = tls_findings([tls(tls_handshake_ms=10.0)], thresholds)
    ids = [f.id for f in findings]
    assert "tls.handshake_slow.cloudflare" not in ids


def test_slow_ttfb_above_threshold_produces_a_finding(thresholds):
    findings = tls_findings([tls(ttfb_ms=900.0)], thresholds)
    ids = [f.id for f in findings]
    assert "tls.ttfb_slow.cloudflare" in ids


def test_server_cpu_bound_fires_when_handshake_dwarfs_tcp_rtt(thresholds):
    findings = tls_findings([tls(tcp_rtt_ms=20.0, tls_handshake_ms=80.0)], thresholds)
    ids = [f.id for f in findings]
    assert "tls.server_cpu_bound.cloudflare" in ids


def test_server_cpu_bound_does_not_fire_on_sub_millisecond_loopback_timings(thresholds):
    # ratio is huge (10x) but absolute handshake time is trivial - not a real CPU-bound server.
    findings = tls_findings([tls(tcp_rtt_ms=1.0, tls_handshake_ms=10.0)], thresholds)
    ids = [f.id for f in findings]
    assert "tls.server_cpu_bound.cloudflare" not in ids


def test_two_tls_targets_get_distinct_finding_ids_so_dedupe_keeps_both(thresholds):
    findings = tls_findings(
        [tls(label="a", host="a.test", tls_handshake_ms=350.0), tls(label="b", host="b.test", tls_handshake_ms=350.0)],
        thresholds,
    )
    ids = {f.id for f in findings if f.id.startswith("tls.handshake_slow")}
    assert ids == {"tls.handshake_slow.a", "tls.handshake_slow.b"}


def test_tls_findings_do_not_crash_on_a_result_with_no_measurements(thresholds):
    assert tls_findings([tls(tcp_rtt_ms=None, tls_handshake_ms=None, ttfb_ms=None)], thresholds) == []


def test_pin_mismatch_fires_a_crit_finding(thresholds):
    findings = tls_findings([tls(pin_verdict="mismatch", cert_sha256="a" * 64)], thresholds)
    assert [f.id for f in findings] == ["tls.cert_pin_mismatch.cloudflare"]
    assert findings[0].severity == "crit"


def test_unverified_cert_without_a_pin_fires_a_warn_finding(thresholds):
    findings = tls_findings([tls(cert_verified=False, cert_issuer="Corp Intercept CA")], thresholds)
    assert [f.id for f in findings] == ["tls.cert_unverified.cloudflare"]
    assert findings[0].severity == "warn"
    assert "Corp Intercept CA" in findings[0].detail


def test_a_verified_unpinned_cert_produces_neither_pin_nor_unverified_findings(thresholds):
    findings = tls_findings([tls(cert_verified=True, pin_verdict="unpinned")], thresholds)
    ids = [f.id for f in findings]
    assert "tls.cert_pin_mismatch.cloudflare" not in ids
    assert "tls.cert_unverified.cloudflare" not in ids


def test_expiring_cert_fires_a_warn_finding(thresholds):
    findings = tls_findings([tls(cert_days_remaining=5, cert_not_after="Jun  1 12:00:00 2026 GMT")], thresholds)
    assert [f.id for f in findings] == ["tls.cert_expiring.cloudflare"]
    assert findings[0].severity == "warn"


def test_cert_with_plenty_of_days_left_does_not_fire(thresholds):
    findings = tls_findings([tls(cert_days_remaining=120)], thresholds)
    assert "tls.cert_expiring.cloudflare" not in [f.id for f in findings]


def prefix_probe(**kw) -> PrefixProbe:
    base = dict(prefix="203.0.113.0/24", probe_ip="203.0.113.1", avg_ms=10.0, reachable=True)
    base.update(kw)
    return PrefixProbe(**base)


def bench(**kw) -> PrefixBenchmark:
    base = dict(asn="AS64500", prefixes_announced=10, prefixes_probed=2, method="icmp")
    base.update(kw)
    return PrefixBenchmark(**base)


def test_empty_prefix_benchmark_produces_no_findings(thresholds):
    assert prefix_findings(bench(results=[]), thresholds) == []


def test_high_spread_produces_a_finding(thresholds):
    results = [prefix_probe(prefix="a/24", avg_ms=5.0, reachable=True), prefix_probe(prefix="b/24", avg_ms=200.0, reachable=True)]
    findings = prefix_findings(bench(results=results, best="a/24", worst="b/24", spread_ms=195.0), thresholds)
    ids = [f.id for f in findings]
    assert "prefix.spread" in ids
    assert findings[[f.id for f in findings].index("prefix.spread")].severity == "crit"


def test_low_spread_produces_no_spread_finding(thresholds):
    results = [prefix_probe(prefix="a/24", avg_ms=10.0), prefix_probe(prefix="b/24", avg_ms=15.0)]
    findings = prefix_findings(bench(results=results, spread_ms=5.0), thresholds)
    assert "prefix.spread" not in [f.id for f in findings]


def test_mostly_unreachable_prefixes_produce_an_info_finding_not_a_warning(thresholds):
    results = [prefix_probe(reachable=False, avg_ms=None) for _ in range(8)] + [prefix_probe(reachable=True)] * 2
    findings = prefix_findings(bench(results=results), thresholds)
    hit = [f for f in findings if f.id == "prefix.mostly_unreachable"]
    assert len(hit) == 1
    assert hit[0].severity == "info"


def test_mostly_reachable_prefixes_produce_no_unreachable_finding(thresholds):
    results = [prefix_probe(reachable=True)] * 10
    findings = prefix_findings(bench(results=results, spread_ms=0.0), thresholds)
    assert "prefix.mostly_unreachable" not in [f.id for f in findings]


def dpi_result(**kw) -> DpiCheckResult:
    base = dict(target="203.0.113.9", resolved_ip="203.0.113.9", consented=True, verdict="clean", rationale="clean", rationale_ru="чисто")
    base.update(kw)
    return DpiCheckResult(**base)


def test_clean_dpi_verdict_produces_no_findings():
    assert dpi_findings(dpi_result(verdict="clean")) == []


def test_reset_injection_verdict_produces_a_crit_finding():
    findings = dpi_findings(dpi_result(verdict="reset_injection", rationale="reset seen", rationale_ru="сброс обнаружен"))
    assert len(findings) == 1
    assert findings[0].id == "dpi.reset_injection"
    assert findings[0].severity == "crit"
    assert has_cyrillic(findings[0].detail_ru)


def test_partial_filtering_verdict_produces_a_warn_finding():
    findings = dpi_findings(dpi_result(verdict="partial_filtering", rationale="mixed", rationale_ru="смешанно"))
    assert findings[0].severity == "warn"
    assert findings[0].id == "dpi.partial_filtering"


def test_unreachable_verdict_produces_only_an_info_finding_not_an_accusation():
    findings = dpi_findings(dpi_result(verdict="unreachable", rationale="or offline", rationale_ru="или выключен"))
    assert findings[0].severity == "info"
    assert findings[0].id == "dpi.unreachable"


def resolver_probe(**kw) -> ResolverProbe:
    base = dict(name="system", kind="system", query_name="example.com", answers=["1.2.3.4"], elapsed_ms=20.0)
    base.update(kw)
    return ResolverProbe(**base)


def dns_adv(**kw) -> DnsAdvanced:
    base = dict(probes=[], note="ok", note_ru="ок")
    base.update(kw)
    return DnsAdvanced(**base)


def test_no_transparent_proxy_and_normal_timing_produce_no_findings(thresholds):
    adv = dns_adv(transparent_proxy=False, system_avg_ms=20.0, doh_avg_ms=25.0)
    assert dns_advanced_findings(adv, thresholds) == []


def test_transparent_proxy_detected_produces_a_warn_finding(thresholds):
    adv = dns_adv(transparent_proxy=True, transparent_proxy_detail="responded")
    findings = dns_advanced_findings(adv, thresholds)
    ids = [f.id for f in findings]
    assert "dns.transparent_proxy" in ids
    assert [f for f in findings if f.id == "dns.transparent_proxy"][0].severity == "warn"


def test_slow_system_resolver_compared_to_doh_produces_a_finding(thresholds):
    adv = dns_adv(transparent_proxy=False, system_avg_ms=200.0, doh_avg_ms=20.0)
    findings = dns_advanced_findings(adv, thresholds)
    assert "dns.system_slow" in [f.id for f in findings]


def test_system_resolver_slower_measurement_but_still_under_threshold_produces_nothing(thresholds):
    adv = dns_adv(transparent_proxy=False, system_avg_ms=25.0, doh_avg_ms=20.0)
    assert dns_advanced_findings(adv, thresholds) == []


def test_cdn_style_divergence_without_a_suspicious_flag_produces_no_poisoning_finding(thresholds):
    adv = dns_adv(divergences=["example.com: system=['1.1.1.1'] vs cloudflare=['104.16.1.1'] (suspicious=False)"])
    findings = dns_advanced_findings(adv, thresholds)
    assert not any(f.id.startswith("dns.poisoned_answer") for f in findings)


def test_suspicious_divergence_produces_a_crit_poisoning_finding_named_after_the_domain(thresholds):
    adv = dns_adv(divergences=["example.com: system=['192.0.2.1'] vs cloudflare=['1.1.1.1'] (suspicious=True)"])
    findings = dns_advanced_findings(adv, thresholds)
    hit = [f for f in findings if f.id == "dns.poisoned_answer.example.com"]
    assert len(hit) == 1
    assert hit[0].severity == "crit"
    assert has_cyrillic(hit[0].title_ru)


def test_dns_advanced_findings_do_not_crash_on_all_none_fields(thresholds):
    assert dns_advanced_findings(dns_adv(), thresholds) == []


def anycast_hop(**kw) -> AnycastHop:
    base = dict(target="cloudflare.com", source="cf_ray")
    base.update(kw)
    return AnycastHop(**base)


def test_no_international_loop_produces_no_loop_finding():
    pd = PathDiversity(client_country="RU", hops=[anycast_hop()], international_loop=False)
    assert "anycast.international_loop" not in [f.id for f in path_diversity_findings(pd)]


def test_international_loop_produces_a_warn_finding():
    pd = PathDiversity(
        client_country="RU",
        hops=[anycast_hop(edge_country="DE")],
        international_loop=True,
        detour_countries=["DE"],
        note="detour",
        note_ru="крюк через Германию",
    )
    findings = path_diversity_findings(pd)
    hit = [f for f in findings if f.id == "anycast.international_loop"]
    assert len(hit) == 1
    assert hit[0].severity == "warn"
    assert has_cyrillic(hit[0].detail_ru)


def test_edge_far_from_client_produces_an_info_finding_named_after_the_target():
    pd = PathDiversity(client_country="RU", hops=[anycast_hop(target="slow.test", client_rtt_ms=150.0, edge_rtt_ms=10.0)])
    findings = path_diversity_findings(pd)
    assert "anycast.edge_far.slow.test" in [f.id for f in findings]


def test_edge_close_to_client_produces_no_edge_far_finding():
    pd = PathDiversity(client_country="RU", hops=[anycast_hop(target="fast.test", client_rtt_ms=12.0, edge_rtt_ms=10.0)])
    findings = path_diversity_findings(pd)
    assert not any(f.id.startswith("anycast.edge_far") for f in findings)


def test_path_diversity_findings_do_not_crash_on_empty_hops():
    assert path_diversity_findings(PathDiversity()) == []
