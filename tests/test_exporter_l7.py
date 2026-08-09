from __future__ import annotations

import json

import pytest

from netsleuth.exporter import (
    SECTION_ORDER,
    _dns_advanced,
    _dpi_check,
    _path_diversity,
    _prefix_benchmark,
    _section_title,
    _tls,
    build_report,
    dump_json,
)
from netsleuth.models import (
    AnycastHop,
    DnsAdvanced,
    DpiCheckResult,
    ModuleResult,
    PathDiversity,
    PortProbe,
    PrefixBenchmark,
    PrefixProbe,
    ResolverProbe,
    TlsResult,
)


def meta() -> dict:
    return {
        "run_id": "b7f1",
        "started_at": "2026-08-08T19:12:00Z",
        "finished_at": "2026-08-08T19:13:04Z",
        "mode": "auto",
        "target": None,
        "flags": {},
        "host_os": "Windows",
        "capabilities": {},
    }


def test_every_section_in_order_has_a_title_in_both_languages():
    for section in SECTION_ORDER:
        assert _section_title(section, "en").startswith("## ")
        assert _section_title(section, "ru").startswith("## ")


@pytest.mark.parametrize(
    ("section", "renderer"),
    [
        ("tls", _tls),
        ("dns_advanced", _dns_advanced),
        ("path_diversity", _path_diversity),
        ("prefix_benchmark", _prefix_benchmark),
        ("dpi_check", _dpi_check),
    ],
)
def test_new_l7_section_shows_a_placeholder_when_skipped(section, renderer):
    report = build_report(meta(), {section: ModuleResult(name=section, status="skipped")}, [], {})
    lines = renderer(report, "en")
    assert any("Not available" in line for line in lines)


def test_tls_section_renders_measurements_and_the_handshake_footnote():
    report = build_report(
        meta(),
        {
            "tls": ModuleResult(
                name="tls",
                status="ok",
                data=[
                    TlsResult(
                        label="cloudflare",
                        host="cloudflare.com",
                        resolved_ip="104.16.132.229",
                        tcp_rtt_ms=12.0,
                        tls_handshake_ms=45.0,
                        ttfb_ms=60.0,
                        tls_version="TLSv1.3",
                        cipher="TLS_AES_256_GCM_SHA384",
                    )
                ],
            )
        },
        [],
        {},
    )
    text = "\n".join(_tls(report, "en"))
    assert "104.16.132.229" in text
    assert "45" in text
    assert "TLSv1.3" in text
    assert "subtracting" in text.lower()


def test_tls_section_lists_errored_targets_separately():
    report = build_report(
        meta(),
        {"tls": ModuleResult(name="tls", status="partial", data=[TlsResult(label="dead", host="dead.test", error="timeout")])},
        [],
        {},
    )
    text = "\n".join(_tls(report, "en"))
    assert "dead" in text
    assert "timeout" in text


def test_dns_advanced_section_renders_probes_and_transparent_proxy_verdict():
    adv = DnsAdvanced(
        probes=[ResolverProbe(name="system", kind="system", query_name="example.com", answers=["1.2.3.4"], elapsed_ms=15.0)],
        transparent_proxy=True,
        transparent_proxy_detail="A response was received from the bogus resolver IP: transparent DNS proxy detected.",
        note="proxy present",
        note_ru="прокси обнаружен",
    )
    report = build_report(meta(), {"dns_advanced": ModuleResult(name="dns_advanced", status="ok", data=adv)}, [], {})
    text = "\n".join(_dns_advanced(report, "en"))
    assert "example.com" in text
    assert "1.2.3.4" in text
    assert "Transparent DNS proxy" in text
    assert "detected" in text


def test_dns_advanced_section_in_russian_translates_the_note():
    adv = DnsAdvanced(transparent_proxy=False, note="clean", note_ru="чисто")
    report = build_report(meta(), {"dns_advanced": ModuleResult(name="dns_advanced", status="ok", data=adv)}, [], {})
    text = "\n".join(_dns_advanced(report, "ru"))
    assert "чисто" in text


def test_path_diversity_section_renders_hops_and_loop_verdict():
    pd = PathDiversity(
        client_country="RU",
        hops=[
            AnycastHop(
                target="cloudflare.com",
                resolved_ip="104.16.132.229",
                edge_colo="FRA",
                edge_city="Frankfurt",
                edge_country="DE",
                edge_rtt_ms=10.0,
                client_rtt_ms=80.0,
                source="cf_ray",
            )
        ],
        international_loop=True,
        detour_countries=["DE"],
        note="Anycast routed traffic through DE.",
        note_ru="Anycast завернул трафик через DE.",
    )
    report = build_report(meta(), {"path_diversity": ModuleResult(name="path_diversity", status="ok", data=pd)}, [], {})
    text = "\n".join(_path_diversity(report, "en"))
    assert "cloudflare.com" in text
    assert "FRA" in text
    assert "Frankfurt" in text
    assert "International routing loop" in text


def test_prefix_benchmark_section_renders_results_and_summary():
    bench = PrefixBenchmark(
        asn="AS64500",
        prefixes_announced=50,
        prefixes_probed=2,
        method="icmp",
        results=[
            PrefixProbe(prefix="203.0.113.0/24", probe_ip="203.0.113.1", avg_ms=12.0, loss_pct=0.0, reachable=True),
            PrefixProbe(prefix="198.51.100.0/24", probe_ip="198.51.100.1", avg_ms=None, loss_pct=100.0, reachable=False),
        ],
        best="203.0.113.0/24",
        worst="203.0.113.0/24",
        spread_ms=None,
    )
    report = build_report(meta(), {"prefix_benchmark": ModuleResult(name="prefix_benchmark", status="ok", data=bench)}, [], {})
    text = "\n".join(_prefix_benchmark(report, "en"))
    assert "203.0.113.0/24" in text
    assert "198.51.100.0/24" in text
    assert "50" in text


def test_dpi_check_section_renders_ports_and_verdict():
    dpi = DpiCheckResult(
        target="203.0.113.9",
        resolved_ip="203.0.113.9",
        consented=True,
        ports=[PortProbe(port=443, state="open", rtt_ms=20.0), PortProbe(port=8443, state="filtered")],
        verdict="partial_filtering",
        rationale="Some ports responded while others were dropped.",
        rationale_ru="Часть портов ответила, часть тихо не ответила.",
    )
    report = build_report(meta(), {"dpi_check": ModuleResult(name="dpi_check", status="ok", data=dpi)}, [], {})
    text = "\n".join(_dpi_check(report, "en"))
    assert "443" in text
    assert "open" in text
    assert "8443" in text
    assert "filtered" in text
    assert "Some ports responded" in text


def test_a_report_with_every_new_section_serializes_with_allow_nan_false():
    modules = {
        "tls": ModuleResult(name="tls", status="ok", data=[TlsResult(label="cf", host="cloudflare.com")]),
        "prefix_benchmark": ModuleResult(name="prefix_benchmark", status="ok", data=PrefixBenchmark()),
        "dpi_check": ModuleResult(name="dpi_check", status="ok", data=DpiCheckResult()),
        "dns_advanced": ModuleResult(name="dns_advanced", status="ok", data=DnsAdvanced()),
        "path_diversity": ModuleResult(name="path_diversity", status="ok", data=PathDiversity()),
    }
    report = build_report(meta(), modules, [], {})
    text = dump_json(report)
    back = json.loads(text)
    assert back["tls"]["data"][0]["host"] == "cloudflare.com"
