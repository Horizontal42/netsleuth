from __future__ import annotations

import pytest

from netsleuth.compare import (
    Change,
    diff_reports,
    finding_changes,
    identity_changes,
    latency_changes,
    load_report,
    render_diff,
    speed_changes,
)


@pytest.fixture()
def before(fixtures_dir):
    return load_report(fixtures_dir / "reports" / "before.json")


@pytest.fixture()
def after(fixtures_dir):
    return load_report(fixtures_dir / "reports" / "after.json")


def by_label(changes: list[Change]) -> dict[str, Change]:
    return {c.label: c for c in changes}


def test_load_report_reads_a_saved_report(before):
    assert before["schema_version"] == 1
    assert before["meta"]["run_id"] == "aaaa1111"


def test_identity_reports_the_egress_and_asn_change(before, after):
    changes = by_label(identity_changes(before, after))
    assert changes["Egress IP"].before == "203.0.113.44"
    assert changes["Egress IP"].after == "198.51.100.7"
    assert changes["ASN"].before == "AS64500"
    assert changes["ASN"].after == "AS64777"
    assert changes["Country"].after == "DE"
    assert changes["Address type"].after == "hosting"


def test_identity_reports_the_vpn_verdict_and_confidence_delta(before, after):
    changes = by_label(identity_changes(before, after))
    assert changes["VPN verdict"].before == "none"
    assert changes["VPN verdict"].after == "confirmed"
    assert changes["VPN confidence"].delta == pytest.approx(0.65)


def test_identity_falls_back_from_as_name_to_org():
    before = {"ip_geo": {"data": {"egress_v4": {"as_name": None, "org": "Fallback Org 1"}}}}
    after = {"ip_geo": {"data": {"egress_v4": {"as_name": "", "org": "Fallback Org 2"}}}}
    changes = by_label(identity_changes(before, after))
    assert changes["Organisation"].before == "Fallback Org 1"
    assert changes["Organisation"].after == "Fallback Org 2"


def test_identity_handles_missing_sections():
    before = {}
    after = {"ip_geo": {"data": {"egress_v4": {"ip": "1.2.3.4"}}}, "vpn_assessment": {"data": {"verdict": "confirmed"}}}
    changes = by_label(identity_changes(before, after))
    assert changes["Egress IP"].before is None
    assert changes["Egress IP"].after == "1.2.3.4"
    assert changes["VPN verdict"].before is None
    assert changes["VPN verdict"].after == "confirmed"

    # Reverse direction
    changes2 = by_label(identity_changes(after, before))
    assert changes2["Egress IP"].before == "1.2.3.4"
    assert changes2["Egress IP"].after is None
    assert changes2["VPN verdict"].before == "confirmed"
    assert changes2["VPN verdict"].after is None


def test_identity_of_a_report_against_itself_is_empty(before):
    assert identity_changes(before, before) == []


def test_latency_deltas_are_signed_per_host_and_metric(before, after):
    changes = by_label(latency_changes(before, after))
    assert changes["cloudflare-dns avg_ms"].delta == pytest.approx(34.5)
    assert changes["cloudflare-dns avg_ms"].before == 12.4
    assert "cloudflare-dns jitter_ms" not in changes


def test_a_host_present_in_only_one_report_is_still_reported(before, after):
    changes = by_label(latency_changes(before, after))
    assert changes["google-dns avg_ms"].after is None
    assert changes["quad9-dns avg_ms"].before is None
    assert changes["quad9-dns avg_ms"].delta is None


def test_latency_of_a_report_against_itself_is_empty(before):
    assert latency_changes(before, before) == []


def test_latency_changes_handles_missing_sections():
    assert latency_changes({}, {}) == []
    assert latency_changes({"latency": None}, {"latency": {"data": None}}) == []


def test_latency_changes_reports_all_metrics():
    before = {
        "latency": {
            "data": [
                {"label": "test-host", "avg_ms": 10.0, "jitter_ms": 2.0, "loss_pct": 0.0}
            ]
        }
    }
    after = {
        "latency": {
            "data": [
                {"label": "test-host", "avg_ms": 15.0, "jitter_ms": 5.0, "loss_pct": 1.5}
            ]
        }
    }
    changes = latency_changes(before, after)
    assert len(changes) == 3
    changes_by_label = {c.label: c for c in changes}
    assert changes_by_label["test-host avg_ms"].delta == 5.0
    assert changes_by_label["test-host jitter_ms"].delta == 3.0
    assert changes_by_label["test-host loss_pct"].delta == 1.5


def test_latency_changes_maintains_sorted_order():
    before = {
        "latency": {
            "data": [
                {"label": "zebra", "avg_ms": 10.0},
                {"label": "alpha", "avg_ms": 20.0},
            ]
        }
    }
    after = {
        "latency": {
            "data": [
                {"label": "zebra", "avg_ms": 11.0},
                {"label": "alpha", "avg_ms": 21.0},
                {"label": "beta", "avg_ms": 30.0},
            ]
        }
    }

    # Ensure after doesn't have beta in before so it shows up as a change
    changes = latency_changes(before, after)

    labels = [c.label for c in changes]
    assert labels == ["alpha avg_ms", "beta avg_ms", "zebra avg_ms"]


def test_speed_deltas_cover_throughput_and_the_bufferbloat_grade(before, after):
    changes = by_label(speed_changes(before, after))
    assert changes["Download Mbps"].delta == pytest.approx(-188.2)
    assert changes["Upload Mbps"].delta == pytest.approx(-3.7)
    assert changes["Bufferbloat grade"].before == "B"
    assert changes["Bufferbloat grade"].after == "D"
    assert "Speedtest method" not in changes


def test_speed_of_a_report_against_itself_is_empty(before):
    assert speed_changes(before, before) == []


def test_speed_changes_with_missing_sections():
    assert speed_changes({}, {}) == []


def test_speed_changes_all_fields():
    before_report = {
        "speed": {
            "data": {
                "method": "fast",
                "download_mbps": 100.0,
                "upload_mbps": 50.0,
                "bufferbloat_down_ms": 10.0,
                "bufferbloat_up_ms": 5.0,
                "bufferbloat_grade": "A",
            }
        }
    }
    after_report = {
        "speed": {
            "data": {
                "method": "cloudflare",
                "download_mbps": 200.0,
                "upload_mbps": 100.0,
                "bufferbloat_down_ms": 20.0,
                "bufferbloat_up_ms": 15.0,
                "bufferbloat_grade": "C",
            }
        }
    }
    changes = by_label(speed_changes(before_report, after_report))

    assert changes["Speedtest method"].before == "fast"
    assert changes["Speedtest method"].after == "cloudflare"
    assert changes["Speedtest method"].delta is None

    assert changes["Download Mbps"].delta == pytest.approx(100.0)
    assert changes["Upload Mbps"].delta == pytest.approx(50.0)
    assert changes["Bufferbloat down ms"].delta == pytest.approx(10.0)
    assert changes["Bufferbloat up ms"].delta == pytest.approx(10.0)

    assert changes["Bufferbloat grade"].before == "A"
    assert changes["Bufferbloat grade"].after == "C"
    assert changes["Bufferbloat grade"].delta is None


def test_findings_are_split_into_new_and_resolved(before, after):
    new, resolved = finding_changes(before, after)
    assert [f["id"] for f in new] == ["speed.bufferbloat_down"]
    assert resolved == []
    new, resolved = finding_changes(after, before)
    assert new == []
    assert [f["id"] for f in resolved] == ["speed.bufferbloat_down"]


def test_finding_changes_empty_inputs():
    assert finding_changes({}, {}) == ([], [])


def test_finding_changes_missing_interpretation_or_findings():
    assert finding_changes({"interpretation": {}}, {"interpretation": {"findings": None}}) == ([], [])
    assert finding_changes({"interpretation": None}, {}) == ([], [])


def test_finding_changes_new_and_resolved_logic():
    before = {
        "interpretation": {
            "findings": [
                {"id": "issue1", "desc": "old issue"},
                {"id": "issue2", "desc": "persisting issue"}
            ]
        }
    }
    after = {
        "interpretation": {
            "findings": [
                {"id": "issue2", "desc": "persisting issue updated"},
                {"id": "issue3", "desc": "new issue"}
            ]
        }
    }
    new, resolved = finding_changes(before, after)
    assert new == [{"id": "issue3", "desc": "new issue"}]
    assert resolved == [{"id": "issue1", "desc": "old issue"}]


def test_diff_reports_assembles_every_part(before, after):
    diff = diff_reports(before, after)
    assert diff.identity
    assert diff.latency
    assert diff.speed
    assert len(diff.new_findings) == 1
    assert diff.resolved_findings == []


def test_render_diff_shows_before_and_after_values(before, after):
    text = render_diff(diff_reports(before, after))
    assert text.startswith("# netsleuth compare")
    assert "203.0.113.44" in text
    assert "198.51.100.7" in text
    assert "-188.2" in text
    assert "Bufferbloat under load" in text


def test_render_diff_of_two_identical_reports_says_so(before):
    text = render_diff(diff_reports(before, before))
    assert text.count("No change.") == 3
    assert "No findings appeared or cleared." in text


def test_render_diff_honours_the_emoji_setting(before, after):
    assert "🔴" in render_diff(diff_reports(before, after), emoji=True)
    assert "[crit]" in render_diff(diff_reports(before, after), emoji=False)
