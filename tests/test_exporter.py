from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from netcheck.exporter import (
    SCHEMA_VERSION,
    SECTION_ORDER,
    atomic_write,
    build_report,
    compact_timestamp,
    dump_json,
    egress_asn,
    flatten_errors,
    report_filename,
    sanitize_name,
    write_report,
)
from netcheck.models import (
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
        "connection",
        "ip_geo",
        "vpn_assessment",
        "bgp",
        "reputation",
        "latency",
        "path",
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


def test_compact_timestamp_strips_the_characters_windows_forbids():
    assert compact_timestamp("2026-08-08T19:12:00Z") == "20260808T191200Z"
    assert compact_timestamp("") == "unknown"


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
        == "report_AS64500_20260808T191200Z.json"
    )
    assert (
        report_filename(None, "2026-08-08T19:12:00Z", "md")
        == "report_unknown_20260808T191200Z.md"
    )


def test_egress_asn_is_read_out_of_the_assembled_report():
    report = build_report(meta(), modules(), [], {})
    assert egress_asn(report) == "AS64500"
    assert egress_asn({"ip_geo": {"data": None}}) is None
    assert egress_asn({}) is None


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


def test_write_report_emits_both_artifacts_with_matching_names(tmp_path: Path):
    report = build_report(meta(), modules(), [], {})
    json_path, md_path = write_report(report, "# netcheck report\n", tmp_path)
    assert json_path.name == "report_AS64500_20260808T191200Z.json"
    assert md_path.name == "report_AS64500_20260808T191200Z.md"
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema_version"] == SCHEMA_VERSION
    assert md_path.read_text(encoding="utf-8").startswith("# netcheck report")
