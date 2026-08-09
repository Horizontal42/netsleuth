from __future__ import annotations

import json

import pytest

from netsleuth.models import (
    AdapterLeakResult,
    AnycastHop,
    BgpEvent,
    BgpIntel,
    Capabilities,
    CfL4Stats,
    CfTrace,
    DnsAdvanced,
    DnsLeak,
    DnsblHit,
    DpiCheckResult,
    Finding,
    InternetDbResult,
    IpGeo,
    IxpPresence,
    LocalNet,
    ModuleResult,
    PathDiversity,
    PingResult,
    PortProbe,
    PrefixBenchmark,
    PrefixProbe,
    ProbeError,
    Reputation,
    ResolverProbe,
    Signal,
    SpeedResult,
    TierAttempt,
    TlsResult,
    TraceHop,
    TraceResult,
    VpnAssessment,
    to_jsonable,
)


def test_probe_error_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown ProbeError kind"):
        ProbeError(source="ip-api", kind="exploded", message="boom")


@pytest.mark.parametrize(
    "kind",
    [
        "timeout",
        "http_error",
        "rate_limited",
        "blocked",
        "parse_error",
        "unavailable",
        "no_privilege",
        "not_applicable",
    ],
)
def test_probe_error_accepts_documented_kinds(kind):
    assert ProbeError(source="s", kind=kind, message="m").kind == kind


def test_module_result_rejects_unknown_status():
    with pytest.raises(ValueError, match="unknown ModuleResult status"):
        ModuleResult(name="bgp", status="borked")


def test_module_result_serializes_to_strict_json():
    result = ModuleResult(
        name="reputation",
        status="partial",
        data={"firehol_hits": ["firehol_level1"]},
        errors=[ProbeError(source="internetdb", kind="timeout", message="8s", retryable=True)],
        warnings=["abuseipdb key missing"],
        started_at="2026-08-08T19:12:00Z",
        duration_ms=1234,
    )
    text = json.dumps(to_jsonable(result), allow_nan=False)
    back = json.loads(text)
    assert back["name"] == "reputation"
    assert back["status"] == "partial"
    assert back["data"]["firehol_hits"] == ["firehol_level1"]
    assert back["errors"][0] == {
        "source": "internetdb",
        "kind": "timeout",
        "message": "8s",
        "retryable": True,
    }
    assert back["warnings"] == ["abuseipdb key missing"]
    assert back["duration_ms"] == 1234


def test_to_jsonable_coerces_non_finite_numbers_to_null():
    payload = {"a": float("inf"), "b": float("-inf"), "c": float("nan"), "d": 1.5}
    out = to_jsonable(payload)
    assert out == {"a": None, "b": None, "c": None, "d": 1.5}
    json.dumps(out, allow_nan=False)


def test_to_jsonable_handles_nested_dataclasses_and_sets():
    finding = Finding(
        id="latency.high",
        severity="warn",
        title="Latency above target",
        detail="avg 130 ms to 1.1.1.1",
        metric="avg_ms",
        value=130.0,
        threshold=100.0,
        advice="Check for a saturated uplink.",
    )
    signal = Signal(name="tunnel_iface", observed=True, weight=0.35, direction="vpn", note="wg0")
    out = to_jsonable({"findings": [finding], "signals": (signal,), "tags": {"a"}})
    assert out["findings"][0]["severity"] == "warn"
    assert out["signals"][0]["weight"] == 0.35
    assert out["tags"] == ["a"]
    json.dumps(out, allow_nan=False)


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError, match="unknown Finding severity"):
        Finding(
            id="x",
            severity="apocalyptic",
            title="t",
            detail="d",
            metric=None,
            value=None,
            threshold=None,
            advice=None,
        )


def test_every_domain_shape_defaults_to_constructible_with_no_arguments():
    for cls in (
        Capabilities,
        LocalNet,
        IpGeo,
        CfTrace,
        VpnAssessment,
        DnsLeak,
        BgpIntel,
        Reputation,
        SpeedResult,
        TraceResult,
    ):
        instance = cls()
        json.dumps(to_jsonable(instance), allow_nan=False)


def test_ping_result_round_trips_through_json():
    ping = PingResult(
        label="cloudflare-dns",
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_win",
        sent=20,
        received=20,
        loss_pct=0.0,
        min_ms=11.0,
        avg_ms=12.4,
        max_ms=15.1,
        mdev_ms=0.9,
        jitter_ms=1.9,
        samples=[11.0, 12.0, None, 15.1],
    )
    out = json.loads(json.dumps(to_jsonable(ping), allow_nan=False))
    assert out["method"] == "icmp_win"
    assert out["samples"][2] is None


def test_trace_result_nests_hops():
    trace = TraceResult(
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        backend="icmp_win",
        hops=[TraceHop(ttl=1, ip="192.168.1.1", probes=[1.2, 1.1, None], annotations=["!H"])],
        cycles=1,
        completed=True,
    )
    out = to_jsonable(trace)
    assert out["hops"][0]["ttl"] == 1
    assert out["hops"][0]["annotations"] == ["!H"]
    assert out["backend"] == "icmp_win"


def test_reputation_composes_optional_sub_results():
    rep = Reputation(
        internetdb=InternetDbResult(ip="203.0.113.44", ports=[80, 443], tags=["cdn"]),
        firehol_hits=["firehol_level1"],
        dnsbl_hits=[DnsblHit(zone="zen.spamhaus.org", codes=["127.0.0.2"], meaning="listed")],
        dnsbl_query_blocked=False,
        captcha_risk="medium",
        rationale="Listed on one blocklist.",
    )
    out = to_jsonable(rep)
    assert out["internetdb"]["ports"] == [80, 443]
    assert out["dnsbl_hits"][0]["zone"] == "zen.spamhaus.org"


def test_bgp_intel_nests_events_and_ixps():
    bgp = BgpIntel(
        asn="AS64500",
        holder="Example Telecom",
        flaps=[BgpEvent(timestamp="2026-08-01T00:00:00Z", type="A", prefix="203.0.113.0/24")],
        ixps=[IxpPresence(name="AMS-IX", city="Amsterdam", country="NL", speed_mbps=100000)],
        stability="stable",
    )
    out = to_jsonable(bgp)
    assert out["flaps"][0]["prefix"] == "203.0.113.0/24"
    assert out["ixps"][0]["speed_mbps"] == 100000


def test_speed_result_carries_tier_attempts_and_cfl4():
    speed = SpeedResult(
        method="cloudflare",
        tier_attempts=[
            TierAttempt(tier="ookla_bin", ok=False, reason="binary not on PATH"),
            TierAttempt(tier="cloudflare", ok=True, reason=None),
        ],
        download_mbps=284.3,
        upload_mbps=41.7,
        cfL4_stats=CfL4Stats(rtt_ms=12.0, min_rtt_ms=11.0, rtt_var_ms=1.5, delivery_rate_bps=35000000, cwnd=42, unsent_bytes=0, recv_bytes=1048576),
    )
    out = to_jsonable(speed)
    assert out["tier_attempts"][0]["ok"] is False
    assert out["cfL4_stats"]["rtt_ms"] == 12.0


def test_adapter_leak_result_and_dns_leak_compose():
    leak = DnsLeak(
        per_adapter=[
            AdapterLeakResult(
                adapter="Wi-Fi",
                configured_resolvers=["192.168.1.1"],
                echoed_ip="203.0.113.9",
                echoed_asn="AS64501",
                matches_egress_asn=False,
            )
        ],
        ecs_leaked=True,
        note="ISP resolver still active on Wi-Fi adapter.",
    )
    out = to_jsonable(leak)
    assert out["per_adapter"][0]["matches_egress_asn"] is False
    assert out["ecs_leaked"] is True


def test_ip_geo_and_vpn_assessment_defaults_are_json_safe():
    geo = IpGeo(ip="203.0.113.44", ip_version=4, asn="AS64500", sources={"asn": "ip-api"})
    vpn = VpnAssessment(verdict="likely", confidence=0.55, signals=[Signal("warp", True, 0.5, "vpn")])
    out = to_jsonable({"geo": geo, "vpn": vpn})
    assert out["geo"]["ip_type"] == "unknown"
    assert out["vpn"]["signals"][0]["name"] == "warp"


def test_every_l7_domain_shape_defaults_to_constructible_with_no_arguments():
    for cls in (TlsResult, PrefixBenchmark, DpiCheckResult, DnsAdvanced, PathDiversity):
        instance = cls()
        json.dumps(to_jsonable(instance), allow_nan=False)


def test_tls_result_round_trips_through_json():
    tls = TlsResult(
        label="cloudflare",
        host="cloudflare.com",
        port=443,
        resolved_ip="104.16.132.229",
        tcp_rtt_ms=12.0,
        tls_handshake_ms=45.0,
        ttfb_ms=60.0,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        alpn="h2",
        cert_verified=True,
    )
    out = json.loads(json.dumps(to_jsonable(tls), allow_nan=False))
    assert out["host"] == "cloudflare.com"
    assert out["tls_handshake_ms"] == 45.0


def test_port_probe_rejects_unknown_state():
    with pytest.raises(ValueError, match="unknown PortProbe state"):
        PortProbe(port=443, state="bogus")


@pytest.mark.parametrize("state", ["open", "closed", "filtered", "reset", "error"])
def test_port_probe_accepts_documented_states(state):
    assert PortProbe(port=443, state=state).state == state


def test_dpi_check_result_rejects_unknown_verdict():
    with pytest.raises(ValueError, match="unknown DpiCheckResult verdict"):
        DpiCheckResult(verdict="bogus")


@pytest.mark.parametrize(
    "verdict", ["clean", "partial_filtering", "reset_injection", "unreachable", "unknown"]
)
def test_dpi_check_result_accepts_documented_verdicts(verdict):
    assert DpiCheckResult(verdict=verdict).verdict == verdict


def test_dpi_check_result_nests_port_probes():
    result = DpiCheckResult(
        target="203.0.113.9",
        resolved_ip="203.0.113.9",
        consented=True,
        ports=[PortProbe(port=443, state="open", rtt_ms=20.0)],
        verdict="clean",
        rationale="all probed ports behave normally",
    )
    out = to_jsonable(result)
    assert out["ports"][0]["state"] == "open"
    assert out["consented"] is True


def test_resolver_probe_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown ResolverProbe kind"):
        ResolverProbe(name="system", kind="bogus", query_name="example.com")


@pytest.mark.parametrize("kind", ["system", "doh"])
def test_resolver_probe_accepts_documented_kinds(kind):
    assert ResolverProbe(name="n", kind=kind, query_name="example.com").kind == kind


def test_dns_advanced_nests_resolver_probes():
    adv = DnsAdvanced(
        probes=[ResolverProbe(name="system", kind="system", query_name="example.com", answers=["1.2.3.4"])],
        system_avg_ms=12.0,
        doh_avg_ms=30.0,
        transparent_proxy=False,
        note="system resolver answered directly",
    )
    out = to_jsonable(adv)
    assert out["probes"][0]["answers"] == ["1.2.3.4"]
    assert out["transparent_proxy"] is False


def test_anycast_hop_rejects_unknown_source():
    with pytest.raises(ValueError, match="unknown AnycastHop source"):
        AnycastHop(target="example.com", source="bogus")


@pytest.mark.parametrize("source", ["cf_ray", "cf_trace", "server_timing", "none"])
def test_anycast_hop_accepts_documented_sources(source):
    assert AnycastHop(target="example.com", source=source).source == source


def test_path_diversity_nests_anycast_hops():
    pd = PathDiversity(
        client_country="RU",
        hops=[AnycastHop(target="cloudflare.com", edge_colo="DME", source="cf_ray")],
        international_loop=False,
    )
    out = to_jsonable(pd)
    assert out["hops"][0]["edge_colo"] == "DME"
    assert out["international_loop"] is False


def test_prefix_benchmark_nests_prefix_probes_and_ranks():
    bench = PrefixBenchmark(
        asn="AS64500",
        prefixes_announced=120,
        prefixes_probed=32,
        method="icmp",
        results=[PrefixProbe(prefix="203.0.113.0/24", probe_ip="203.0.113.1", avg_ms=15.0, reachable=True)],
        best="203.0.113.0/24",
    )
    out = to_jsonable(bench)
    assert out["results"][0]["avg_ms"] == 15.0
    assert out["best"] == "203.0.113.0/24"
