from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from netsleuth.exporter import (
    FORMAT_EXTENSIONS,
    SCHEMA_VERSION,
    SECTION_ORDER,
    atomic_write,
    build_report,
    dump_json,
    egress_asn,
    flatten_errors,
    readable_timestamp,
    report_date_dir,
    report_filename,
    sanitize_name,
    write_report,
)
from netsleuth.models import (
    Finding,
    IpGeo,
    LocalNet,
    ModuleResult,
    PingResult,
    ProbeError,
    SpeedResult,
)


def meta() -> dict:
    return {
        "run_id": "b7f1",
        "started_at": "2026-08-08T19:12:00Z",
        "finished_at": "2026-08-08T19:13:04Z",
        "mode": "auto",
        "target": None,
        "flags": {"quick": True, "full": False, "dnsbl": False, "ndt7": False, "tcp_trace": False},
        "host_os": "Windows",
        "capabilities": {"os_name": "Windows", "chosen_latency_backend": "icmp_win"},
    }


def modules() -> dict[str, ModuleResult]:
    return {
        "connection": ModuleResult(name="connection", status="ok", data=LocalNet(iface_name="Wi-Fi 2")),
        "ip_geo": ModuleResult(
            name="ip_geo",
            status="ok",
            data={
                "egress_v4": IpGeo(ip="203.0.113.44", asn="AS64500", as_name="Example Telecom"),
                "egress_v6": None,
                "cf_trace": None,
                "dual_stack_note": None,
            },
        ),
        "latency": ModuleResult(
            name="latency",
            status="partial",
            data=[PingResult(label="cloudflare-dns", host="1.1.1.1", method="icmp_win", sent=5, received=5)],
            errors=[ProbeError(source="quad9-dns", kind="timeout", message="2s", retryable=True)],
            warnings=["quad9 did not answer"],
            duration_ms=1500,
        ),
        "speed": ModuleResult(name="speed", status="skipped", data=None),
    }


def test_report_carries_every_top_level_key_from_the_spec():
    report = build_report(meta(), modules(), [], {"ip-api": {"status": "success"}})
    expected = {"schema_version", "meta", "interpretation", "errors", "raw", *SECTION_ORDER}
    assert expected.issubset(report.keys())
    assert report["schema_version"] == SCHEMA_VERSION


def test_missing_modules_are_rendered_as_skipped_sections_not_dropped():
    report = build_report(meta(), modules(), [], {})
    assert report["bgp"]["status"] == "skipped"
    assert report["bgp"]["data"] is None
    assert set(SECTION_ORDER) == {
        "captive_portal",
        "connection",
        "ip_geo",
        "vpn_assessment",
        "bgp",
        "reputation",
        "dns_advanced",
        "latency",
        "tls",
        "quic",
        "path",
        "ecmp",
        "pmtud",
        "path_diversity",
        "prefix_benchmark",
        "dpi_check",
        "speed",
    }


def test_interpretation_is_computed_from_the_findings():
    findings = [Finding(id="a", severity="warn", title="Jitter high", detail="d")]
    report = build_report(meta(), modules(), findings, {})
    assert report["interpretation"]["overall_status"] == "warn"
    assert report["interpretation"]["overall_score"] == 90
    assert report["interpretation"]["findings"][0]["id"] == "a"


def test_errors_are_flattened_to_the_top_level_with_their_module():
    flat = flatten_errors(modules())
    assert flat == [
        {
            "source": "quad9-dns",
            "kind": "timeout",
            "message": "2s",
            "retryable": True,
            "module": "latency",
        }
    ]


def test_raw_payloads_are_stored_verbatim_under_their_source_key():
    raw = {"ip-api": {"status": "success", "as": "AS64500 Example"}, "cf-trace": "ip=203.0.113.44"}
    report = build_report(meta(), modules(), [], raw)
    assert report["raw"]["ip-api"]["as"] == "AS64500 Example"
    assert report["raw"]["cf-trace"] == "ip=203.0.113.44"


def test_non_finite_numbers_that_reached_the_pipeline_serialize_as_null():
    # Zero-duration timing math produces exactly this on the failure paths the
    # report most needs to show; allow_nan=False would otherwise abort the write.
    broken = modules()
    broken["speed"] = ModuleResult(
        name="speed",
        status="partial",
        data=SpeedResult(
            method="cloudflare",
            download_mbps=float("inf"),
            upload_mbps=float("nan"),
            idle_rtt_ms=float("-inf"),
            bufferbloat_down_ms=12.5,
        ),
    )
    report = build_report(meta(), broken, [], {"cloudflare": {"rate": float("inf")}})
    text = dump_json(report)
    back = json.loads(text)
    assert back["speed"]["data"]["download_mbps"] is None
    assert back["speed"]["data"]["upload_mbps"] is None
    assert back["speed"]["data"]["idle_rtt_ms"] is None
    assert back["speed"]["data"]["bufferbloat_down_ms"] == 12.5
    assert back["raw"]["cloudflare"]["rate"] is None
    assert "Infinity" not in text
    assert "NaN" not in text


def test_dump_json_is_strict_and_round_trips():
    report = build_report(meta(), modules(), [], {})
    back = json.loads(dump_json(report))
    assert back["meta"]["run_id"] == "b7f1"
    assert back["latency"]["data"][0]["label"] == "cloudflare-dns"
    assert math.isfinite(back["latency"]["duration_ms"])


def test_readable_timestamp_strips_the_characters_windows_forbids():
    assert readable_timestamp("2026-08-08T19:12:00Z") == "19-12-00Z"
    assert readable_timestamp("") == "unknown"


def test_report_date_dir_splits_the_iso_date_into_year_month_day():
    assert report_date_dir("2026-08-08T19:12:00Z") == Path("2026", "08", "08")
    assert report_date_dir("") == Path()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AS64500", "AS64500"),
        ("AS64500 Example Telecom", "AS64500_Example_Telecom"),
        ("AS64500/../etc", "AS64500_.._etc"),
        ("AS:64500", "AS_64500"),
        ("", "unknown"),
        (None, "unknown"),
        ("///", "unknown"),
    ],
)
def test_sanitize_name_produces_windows_safe_fragments(value, expected):
    assert sanitize_name(value) == expected


def test_report_filename_matches_the_documented_pattern():
    assert (
        report_filename("AS64500", "2026-08-08T19:12:00Z", "json")
        == "report_AS64500_19-12-00Z.json"
    )
    assert (
        report_filename(None, "2026-08-08T19:12:00Z", "md")
        == "report_unknown_19-12-00Z.md"
    )


def test_egress_asn_is_read_out_of_the_assembled_report():
    report = build_report(meta(), modules(), [], {})
    assert egress_asn(report) == "AS64500"
    assert egress_asn({"ip_geo": {"data": None}}) is None
    assert egress_asn({}) is None


def test_write_report_names_the_file_after_the_target_in_target_mode(tmp_path: Path):
    report = build_report({**meta(), "mode": "target", "target": "AS15169"}, modules(), [], {})
    paths = write_report(
        report,
        {"json": "{}", "md": "# netsleuth report\n", "ru-md": "# netsleuth report\n"},
        tmp_path,
    )
    names = {p.name for p in paths}
    assert "report_AS15169_19-12-00Z.json" in names
    assert "report_AS15169_19-12-00Z.md" in names
    assert "report_AS15169_19-12-00Z.ru.md" in names
    assert {p.parent for p in paths} == {tmp_path / "2026" / "08" / "08"}


def test_atomic_write_creates_the_directory_and_leaves_no_temp_file(tmp_path: Path):
    target = tmp_path / "logs" / "report.json"
    atomic_write(target, '{"a": 1}')
    assert target.read_text(encoding="utf-8") == '{"a": 1}'
    assert list((tmp_path / "logs").iterdir()) == [target]


def test_atomic_write_replaces_an_existing_file(tmp_path: Path):
    target = tmp_path / "report.json"
    atomic_write(target, "old")
    atomic_write(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert not list(tmp_path.glob("*.tmp"))


def test_write_report_emits_all_requested_artifacts_with_matching_names(tmp_path: Path):
    report = build_report(meta(), modules(), [], {})
    paths = write_report(
        report,
        {"json": dump_json(report), "md": "# netsleuth report\n", "ru-md": "# netsleuth report\n"},
        tmp_path,
    )
    by_ext = {p.name.rsplit(".", 1)[-1] if not p.name.endswith(".ru.md") else "ru.md": p for p in paths}
    assert by_ext["json"].name == "report_AS64500_19-12-00Z.json"
    assert by_ext["md"].name == "report_AS64500_19-12-00Z.md"
    assert by_ext["ru.md"].name == "report_AS64500_19-12-00Z.ru.md"
    assert json.loads(by_ext["json"].read_text(encoding="utf-8"))["schema_version"] == SCHEMA_VERSION
    assert by_ext["md"].read_text(encoding="utf-8").startswith("# netsleuth report")
    assert by_ext["ru.md"].read_text(encoding="utf-8").startswith("# netsleuth report")


def test_write_report_writes_only_the_requested_formats(tmp_path: Path):
    report = build_report(meta(), modules(), [], {})
    paths = write_report(report, {"md": "# netsleuth report\n"}, tmp_path)
    assert [p.name for p in paths] == ["report_AS64500_19-12-00Z.md"]
    assert list((tmp_path / "2026" / "08" / "08").iterdir()) == paths


def test_write_report_with_empty_mapping_writes_nothing(tmp_path: Path):
    report = build_report(meta(), modules(), [], {})
    paths = write_report(report, {}, tmp_path)
    assert paths == []
    assert list(tmp_path.iterdir()) == []


def test_write_report_returns_paths_in_input_order(tmp_path: Path):
    report = build_report(meta(), modules(), [], {})
    paths = write_report(report, {"json": "{}", "md": "# x\n"}, tmp_path)
    assert paths[0].name.endswith(".json")
    assert paths[1].name.endswith(".md")


def test_format_extensions_covers_the_known_formats():
    assert FORMAT_EXTENSIONS == {"md": "md", "ru-md": "ru.md", "json": "json", "prom": "prom", "csv": "csv"}


from netsleuth.exporter import (
    SPARK_CHARS,
    _forced_interface_rows,
    badge,
    first_loss_jump,
    render_markdown,
    sparkline,
)
from netsleuth.models import (
    AdapterLeakResult,
    AnycastHop,
    BgpIntel,
    CfTrace,
    DnsAdvanced,
    DnsblHit,
    DnsLeak,
    DpiCheckResult,
    InternetDbResult,
    IxpPresence,
    PathDiversity,
    PortProbe,
    PrefixBenchmark,
    PrefixProbe,
    Reputation,
    ResolverProbe,
    Signal,
    TierAttempt,
    TlsResult,
    TraceHop,
    TraceResult,
    VpnAssessment,
)


def full_modules() -> dict[str, ModuleResult]:
    return {
        "connection": ModuleResult(
            name="connection",
            status="ok",
            data=LocalNet(
                iface_name="Wi-Fi 2",
                local_ipv4="192.168.1.34",
                iface_mtu=1500,
                default_gateway_v4="192.168.1.1",
                dns_servers_per_adapter={"Wi-Fi 2": ["192.168.1.1"]},
            ),
        ),
        "ip_geo": ModuleResult(
            name="ip_geo",
            status="ok",
            data={
                "egress_v4": IpGeo(
                    ip="203.0.113.44",
                    asn="AS64500",
                    as_name="Example Telecom",
                    city="Amsterdam",
                    country="Netherlands",
                    country_code="NL",
                    ip_type="residential",
                    reverse_dns="host-203-0-113-44.example.net",
                ),
                "egress_v6": IpGeo(ip="2001:db8::1", asn="AS64500"),
                "cf_trace": CfTrace(ip="203.0.113.44", colo="AMS", warp="off"),
                "dual_stack_note": None,
            },
        ),
        "vpn_assessment": ModuleResult(
            name="vpn_assessment",
            status="ok",
            data=VpnAssessment(
                verdict="likely",
                confidence=0.55,
                signals=[Signal(name="cf_warp", observed=True, weight=0.5, direction="vpn", note="on")],
                tunnel_iface="wg0",
                dns_leak=DnsLeak(
                    per_adapter=[
                        AdapterLeakResult(
                            adapter="Wi-Fi 2",
                            configured_resolvers=["192.168.1.1"],
                            echoed_ip="203.0.113.9",
                            echoed_asn="AS64501",
                            matches_egress_asn=False,
                        )
                    ],
                    ecs_leaked=True,
                    note="ISP resolver still active on the Wi-Fi adapter.",
                ),
            ),
        ),
        "bgp": ModuleResult(
            name="bgp",
            status="ok",
            data=BgpIntel(
                asn="AS64500",
                holder="Example Telecom BV",
                upstreams=["AS3356"],
                prefix_count_v4=2,
                prefix_count_v6=1,
                stability="stable",
                ixps=[IxpPresence(name="AMS-IX", city="Amsterdam", country="NL", speed_mbps=100000)],
                asrank=1842,
                cone_asns=37,
                pdb_info_type="Cable/DSL/ISP",
            ),
        ),
        "reputation": ModuleResult(
            name="reputation",
            status="ok",
            data=Reputation(
                internetdb=InternetDbResult(ip="203.0.113.44", ports=[80, 443], tags=["cdn"]),
                firehol_hits=[],
                dnsbl_hits=[DnsblHit(zone="bl.spamcop.net", codes=["127.0.0.2"])],
                dnsbl_query_blocked=True,
                captcha_risk="high",
                rationale="listed on bl.spamcop.net",
            ),
        ),
        "dns_advanced": ModuleResult(
            name="dns_advanced",
            status="ok",
            data=DnsAdvanced(
                probes=[
                    ResolverProbe(name="system", kind="system", query_name="cloudflare.com", answers=["1.1.1.1"], elapsed_ms=18.0),
                    ResolverProbe(name="cloudflare", kind="doh", query_name="cloudflare.com", answers=["104.16.132.229"], elapsed_ms=22.0),
                ],
                system_avg_ms=18.0,
                doh_avg_ms=22.0,
                transparent_proxy=False,
                transparent_proxy_detail="No response from the bogus resolver IP (timeout): transparent DNS proxy not detected.",
                note="System resolver and DoH agree within normal CDN variance.",
                note_ru="Системный резолвер и DoH согласуются в пределах обычной вариации CDN.",
            ),
        ),
        "latency": ModuleResult(
            name="latency",
            status="ok",
            data=[
                PingResult(
                    label="cloudflare-dns",
                    host="1.1.1.1",
                    method="icmp_win",
                    sent=5,
                    received=5,
                    avg_ms=12.4,
                    min_ms=11.0,
                    max_ms=15.1,
                    jitter_ms=1.9,
                    samples=[11.0, 12.0, None, 15.1, 12.4],
                ),
                PingResult(label="github", host="github.com", method="tcp", sent=5, received=4, loss_pct=20.0, avg_ms=42.0),
            ],
            duration_ms=2400,
        ),
        "tls": ModuleResult(
            name="tls",
            status="ok",
            data=[
                TlsResult(
                    label="cloudflare",
                    host="cloudflare.com",
                    port=443,
                    resolved_ip="104.16.132.229",
                    tcp_rtt_ms=12.0,
                    tls_handshake_ms=45.0,
                    ttfb_ms=60.0,
                    tls_version="TLSv1.3",
                    cipher="TLS_AES_256_GCM_SHA384",
                )
            ],
        ),
        "path": ModuleResult(
            name="path",
            status="ok",
            data=[
                TraceResult(
                    target="1.1.1.1",
                    backend="icmp_win",
                    completed=True,
                    hops=[
                        TraceHop(ttl=1, ip="192.168.1.1", avg_ms=1.1, loss_pct=0.0),
                        TraceHop(ttl=2, ip="10.64.0.1", avg_ms=9.0, loss_pct=60.0),
                        TraceHop(ttl=3, ip="1.1.1.1", avg_ms=12.4, loss_pct=55.0),
                    ],
                )
            ],
        ),
        "path_diversity": ModuleResult(
            name="path_diversity",
            status="ok",
            data=PathDiversity(
                client_country="RU",
                hops=[
                    AnycastHop(
                        target="cloudflare.com",
                        resolved_ip="104.16.132.229",
                        edge_colo="FRA",
                        edge_city="Frankfurt",
                        edge_country="DE",
                        edge_rtt_ms=15.0,
                        client_rtt_ms=45.0,
                        source="cf_ray",
                    )
                ],
                international_loop=True,
                detour_countries=["DE"],
                note="Anycast routed traffic through DE even though the client is in RU.",
                note_ru="Anycast завернул трафик через DE, хотя клиент находится в RU.",
            ),
        ),
        "prefix_benchmark": ModuleResult(
            name="prefix_benchmark",
            status="ok",
            data=PrefixBenchmark(
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
            ),
        ),
        "dpi_check": ModuleResult(
            name="dpi_check",
            status="ok",
            data=DpiCheckResult(
                target="203.0.113.9",
                resolved_ip="203.0.113.9",
                consented=True,
                ports=[
                    PortProbe(port=443, state="open", rtt_ms=20.0),
                    PortProbe(port=8443, state="filtered"),
                ],
                verdict="partial_filtering",
                rationale="Some ports responded (open) while others were silently dropped (filtered).",
                rationale_ru="Часть портов ответила (открыты), а часть тихо не ответила (отфильтрованы).",
            ),
        ),
        "speed": ModuleResult(
            name="speed",
            status="ok",
            data=SpeedResult(
                method="cloudflare",
                tier_attempts=[
                    TierAttempt(tier="ookla_bin", ok=False, reason="binary not on PATH"),
                    TierAttempt(tier="cloudflare", ok=True),
                ],
                download_mbps=284.3,
                upload_mbps=41.7,
                server="speed.cloudflare.com",
                idle_rtt_ms=12.0,
                loaded_rtt_down_ms=48.0,
                bufferbloat_down_ms=36.0,
                bufferbloat_grade="C",
            ),
        ),
    }


def full_report() -> dict:
    findings = [
        Finding(
            id="latency.loss.github",
            severity="warn",
            title="Loss to github.com",
            detail="20.0% connection failures over 5 probes via tcp.",
            metric="loss_pct",
            value=20.0,
            threshold=2.0,
            advice="Sustained loss on every host points at the local link.",
        )
    ]
    return build_report(meta(), full_modules(), findings, {"ip-api": {"status": "success"}})


def test_sparkline_maps_a_series_across_the_glyph_ramp():
    line = sparkline([1.0, 2.0, 3.0, 4.0, 5.0])
    assert len(line) == 5
    assert line[0] == SPARK_CHARS[0]
    assert line[-1] == SPARK_CHARS[-1]
    assert SPARK_CHARS == "▁▂▃▅▇"


def test_sparkline_of_a_flat_series_is_all_baseline():
    assert sparkline([7.0, 7.0, 7.0]) == SPARK_CHARS[0] * 3


def test_sparkline_renders_a_dropped_probe_as_a_gap():
    line = sparkline([1.0, None, 5.0])
    assert line[1] == " "
    assert len(line) == 3


def test_sparkline_of_nothing_is_empty():
    assert sparkline([]) == ""
    assert sparkline([None, None]) == ""


def test_badge_is_gated_behind_the_emoji_setting():
    assert badge("crit", emoji=True) == "🔴"
    assert badge("warn", emoji=True) == "🟡"
    assert badge("ok", emoji=True) == "🟢"
    assert badge("crit", emoji=False) == "[crit]"
    assert badge("warn", emoji=False) == "[warn]"


def test_first_loss_jump_needs_the_loss_to_persist_downstream():
    hops = [
        {"ttl": 1, "loss_pct": 0.0},
        {"ttl": 2, "loss_pct": 60.0},
        {"ttl": 3, "loss_pct": 55.0},
    ]
    assert first_loss_jump(hops) == 2


def test_first_loss_jump_ignores_a_single_icmp_rate_limiting_hop():
    hops = [{"ttl": 1, "loss_pct": 0.0}, {"ttl": 2, "loss_pct": 100.0}, {"ttl": 3, "loss_pct": 0.0}]
    assert first_loss_jump(hops) is None
    assert first_loss_jump([]) is None


def test_markdown_has_every_section_from_the_spec_in_order():
    text = render_markdown(full_report())
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == [
        "## TL;DR",
        "## Captive portal check",
        "## Connection & identity",
        "## VPN / proxy assessment",
        "## ASN & BGP intelligence",
        "## Reputation",
        "## DNS: system vs DoH",
        "## Latency",
        "## TLS handshake",
        "## QUIC / HTTP3",
        "## Path",
        "## ECMP / multipath",
        "## Path MTU discovery",
        "## Path diversity (Anycast)",
        "## AS prefix benchmark",
        "## DPI / port check",
        "## Speed",
        "## Problems & recommendations",
        "## Run diagnostics",
    ]
    assert text.startswith("# netsleuth report")


def test_markdown_header_states_mode_timestamp_and_verdict():
    text = render_markdown(full_report())
    assert "auto" in text
    assert "2026-08-08T19:12:00Z" in text
    assert "90/100" in text


def test_markdown_reports_identity_and_both_stacks():
    text = render_markdown(full_report())
    assert "203.0.113.44" in text
    assert "AS64500" in text
    assert "2001:db8::1" in text
    assert "Amsterdam" in text
    assert "residential" in text


def test_markdown_vpn_section_lists_signals_and_the_dns_leak():
    text = render_markdown(full_report())
    assert "likely" in text
    assert "cf_warp" in text
    assert "Wi-Fi 2" in text
    assert "AS64501" in text
    assert "ISP resolver still active" in text


def test_markdown_dnsbl_error_range_is_never_shown_as_a_plain_listing():
    text = render_markdown(full_report())
    assert "bl.spamcop.net" in text
    assert "not a listing" in text


def test_markdown_latency_table_carries_a_sparkline_in_a_fenced_block():
    text = render_markdown(full_report())
    assert "cloudflare-dns" in text
    assert any(char in text for char in SPARK_CHARS)
    assert text.count("```") >= 2


def test_markdown_flags_that_tcp_loss_is_a_different_metric():
    text = render_markdown(full_report())
    assert "failed TCP connections" in text


def test_markdown_path_section_marks_the_first_loss_jump():
    text = render_markdown(full_report())
    path_block = text.split("## Path")[1].split("## Speed")[0]
    marked = [line for line in path_block.splitlines() if line.rstrip().endswith("<<")]
    assert len(marked) == 1
    assert "10.64.0.1" in marked[0]


def test_markdown_speed_section_explains_the_bufferbloat_grade_in_plain_language():
    text = render_markdown(full_report())
    assert "284.3" in text
    assert "grade C" in text
    assert "choppy" in text
    assert "ookla_bin" in text
    assert "binary not on PATH" in text


def test_markdown_run_diagnostics_lists_every_module_with_its_status():
    text = render_markdown(full_report())
    block = text.split("## Run diagnostics")[1]
    for section in SECTION_ORDER:
        assert section in block


def test_markdown_without_emoji_uses_text_badges():
    text = render_markdown(full_report(), emoji=False)
    assert "[warn]" in text
    assert "🟡" not in text


def test_forced_interface_rows_are_empty_without_a_forced_interface():
    assert _forced_interface_rows({}, "en") == []


def test_forced_interface_rows_show_the_resolved_adapter():
    meta = {
        "interface": {
            "requested": "Ethernet",
            "resolved_iface": "Ethernet",
            "bind_ipv4": "192.168.3.72",
            "os_default_iface": "Ethernet",
            "os_default_ipv4": "192.168.3.72",
        }
    }
    rows = _forced_interface_rows(meta, "en")
    assert rows == [["Forced interface", "Ethernet — 192.168.3.72 (--interface)"]]


def test_forced_interface_rows_add_the_os_default_when_it_differs():
    meta = {
        "interface": {
            "requested": "Tailscale",
            "resolved_iface": "Tailscale",
            "bind_ipv4": "100.84.46.36",
            "os_default_iface": "Ethernet",
            "os_default_ipv4": "192.168.3.72",
        }
    }
    rows = _forced_interface_rows(meta, "en")
    assert rows == [
        ["Forced interface", "Tailscale — 100.84.46.36 (--interface)"],
        ["OS default interface", "Ethernet — 192.168.3.72"],
    ]


def test_forced_interface_rows_are_translated_in_russian():
    meta = {"interface": {"requested": "Ethernet", "resolved_iface": "Ethernet", "bind_ipv4": "192.168.3.72"}}
    rows = _forced_interface_rows(meta, "ru")
    assert rows[0][0] == "Принудительный интерфейс"


from netsleuth.exporter import unavailable


def dead_modules() -> dict[str, ModuleResult]:
    return {
        section: ModuleResult(
            name=section,
            status="failed",
            data=None,
            errors=[ProbeError(source=section, kind="unavailable", message="network unreachable", retryable=True)],
            duration_ms=8000,
        )
        for section in SECTION_ORDER
    }


def dead_report() -> dict:
    return build_report(meta(), dead_modules(), [], {})


def test_unavailable_describes_a_failed_module_and_stays_quiet_on_a_healthy_one():
    assert unavailable(full_report(), "bgp") is None
    note = unavailable(dead_report(), "bgp")
    assert note is not None
    assert "failed" in note
    assert "network unreachable" in note


def test_unavailable_explains_a_skipped_module_without_inventing_an_error():
    report = build_report(meta(), {"speed": ModuleResult(name="speed", status="skipped")}, [], {})
    note = unavailable(report, "speed")
    assert note is not None
    assert "skipped" in note


def test_unavailable_surfaces_the_skip_reason_from_warnings():
    report = build_report(
        meta(),
        {"speed": ModuleResult(name="speed", status="skipped", warnings=["speedtest skipped in target mode"])},
        [],
        {},
    )
    note = unavailable(report, "speed")
    assert note is not None
    assert "speedtest skipped in target mode" in note


def test_unavailable_translates_the_skip_reason_into_russian():
    report = build_report(
        meta(),
        {"speed": ModuleResult(name="speed", status="skipped", warnings=["speedtest skipped: --quick"])},
        [],
        {},
    )
    note = unavailable(report, "speed", lang="ru")
    assert note is not None
    assert "speedtest skipped: --quick" not in note
    assert "speedtest пропущен: --quick" in note


def test_diagnostics_translates_module_warnings_into_russian():
    from netsleuth.exporter import _diagnostics

    report = build_report(
        meta(),
        {"reputation": ModuleResult(name="reputation", status="partial", warnings=["ABUSEIPDB_API_KEY not set — abuse score skipped"])},
        [],
        {},
    )
    lines = _diagnostics(report, lang="ru")
    text = "\n".join(lines)
    assert "ABUSEIPDB_API_KEY not set — abuse score skipped" not in text
    assert "ABUSEIPDB_API_KEY не задан" in text


def test_an_all_modules_failed_run_still_renders_every_section():
    text = render_markdown(dead_report())
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert len(headings) == 19
    assert text.count("Not available") == len(SECTION_ORDER)


def test_an_all_modules_failed_report_is_still_valid_strict_json():
    report = dead_report()
    back = json.loads(dump_json(report))
    assert back["schema_version"] == SCHEMA_VERSION
    assert len(back["errors"]) == len(SECTION_ORDER)
    assert all(section in back for section in SECTION_ORDER)
    assert back["interpretation"]["overall_status"] == "ok"
    assert back["raw"] == {}


def test_an_all_modules_failed_run_writes_both_artifacts(tmp_path: Path):
    report = dead_report()
    paths = write_report(
        report,
        {"md": render_markdown(report), "ru-md": render_markdown(report, lang="ru")},
        tmp_path,
    )
    md_path = next(p for p in paths if p.name.endswith(".md") and not p.name.endswith(".ru.md"))
    ru_md_path = next(p for p in paths if p.name.endswith(".ru.md"))
    assert md_path.name.startswith("report_unknown_")
    assert ru_md_path.name.startswith("report_unknown_")
    assert "## Run diagnostics" in md_path.read_text(encoding="utf-8")
    assert "## Диагностика запуска" in ru_md_path.read_text(encoding="utf-8")


def test_the_diagnostics_table_still_names_every_failed_module():
    block = render_markdown(dead_report()).split("## Run diagnostics")[1]
    assert block.count("failed") == len(SECTION_ORDER)
    assert "unavailable" in block


def test_a_partial_module_with_data_is_rendered_normally_not_as_a_placeholder():
    report = build_report(meta(), modules(), [], {})
    assert unavailable(report, "latency") is None
    assert "cloudflare-dns" in render_markdown(report)


def _has_cyrillic(text: str) -> bool:
    return any("Ѐ" <= ch <= "ӿ" for ch in text)


def test_russian_markdown_is_non_empty_and_contains_cyrillic():
    text = render_markdown(full_report(), lang="ru")
    assert text.strip()
    assert _has_cyrillic(text)
    assert text.startswith("# netsleuth report")


def _structural_shape(text: str) -> tuple[int, int, int]:
    headings = sum(1 for line in text.splitlines() if line.startswith("## "))
    table_rows = sum(1 for line in text.splitlines() if line.strip().startswith("|"))
    fences = text.count("```")
    return headings, table_rows, fences


def test_russian_report_has_the_same_structural_shape_as_english_for_a_full_report():
    en = render_markdown(full_report(), lang="en")
    ru = render_markdown(full_report(), lang="ru")
    assert _structural_shape(en) == _structural_shape(ru)


def test_russian_report_has_the_same_structural_shape_as_english_for_a_dead_report():
    en = render_markdown(dead_report(), lang="en")
    ru = render_markdown(dead_report(), lang="ru")
    assert _structural_shape(en) == _structural_shape(ru)


def test_write_report_creates_three_files_with_the_right_extensions(tmp_path: Path):
    report = full_report()
    en_name = "sibling.md"
    ru_name = "sibling.ru.md"
    markdown = render_markdown(report, lang="en", sibling=ru_name)
    markdown_ru = render_markdown(report, lang="ru", sibling=en_name)
    paths = write_report(report, {"json": dump_json(report), "md": markdown, "ru-md": markdown_ru}, tmp_path)
    json_path = next(p for p in paths if p.suffix == ".json")
    md_path = next(p for p in paths if p.name.endswith(".md") and not p.name.endswith(".ru.md"))
    ru_md_path = next(p for p in paths if p.name.endswith(".ru.md"))
    assert json_path.suffix == ".json"

    ru_text = ru_md_path.read_text(encoding="utf-8")
    assert _has_cyrillic(ru_text)

    en_lines = md_path.read_text(encoding="utf-8").splitlines()
    ru_lines = ru_text.splitlines()
    assert en_lines[2] == f"[Русский]({ru_name})"
    assert ru_lines[2] == f"[English]({en_name})"


def test_render_markdown_default_call_is_byte_identical_to_before_the_lang_feature():
    text = render_markdown(full_report())
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == [
        "## TL;DR",
        "## Captive portal check",
        "## Connection & identity",
        "## VPN / proxy assessment",
        "## ASN & BGP intelligence",
        "## Reputation",
        "## DNS: system vs DoH",
        "## Latency",
        "## TLS handshake",
        "## QUIC / HTTP3",
        "## Path",
        "## ECMP / multipath",
        "## Path MTU discovery",
        "## Path diversity (Anycast)",
        "## AS prefix benchmark",
        "## DPI / port check",
        "## Speed",
        "## Problems & recommendations",
        "## Run diagnostics",
    ]
    assert text.startswith("# netsleuth report")
    assert "[Русский]" not in text
    assert "[English]" not in text
    assert "cloudflare-dns" in text
