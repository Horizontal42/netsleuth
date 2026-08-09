from __future__ import annotations

import pytest

from netcheck.compare import (
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


def test_speed_deltas_cover_throughput_and_the_bufferbloat_grade(before, after):
    changes = by_label(speed_changes(before, after))
    assert changes["Download Mbps"].delta == pytest.approx(-188.2)
    assert changes["Upload Mbps"].delta == pytest.approx(-3.7)
    assert changes["Bufferbloat grade"].before == "B"
    assert changes["Bufferbloat grade"].after == "D"
    assert "Speedtest method" not in changes


def test_findings_are_split_into_new_and_resolved(before, after):
    new, resolved = finding_changes(before, after)
    assert [f["id"] for f in new] == ["speed.bufferbloat_down"]
    assert resolved == []
    new, resolved = finding_changes(after, before)
    assert new == []
    assert [f["id"] for f in resolved] == ["speed.bufferbloat_down"]


def test_diff_reports_assembles_every_part(before, after):
    diff = diff_reports(before, after)
    assert diff.identity
    assert diff.latency
    assert diff.speed
    assert len(diff.new_findings) == 1
    assert diff.resolved_findings == []


def test_render_diff_shows_before_and_after_values(before, after):
    text = render_diff(diff_reports(before, after))
    assert text.startswith("# netcheck compare")
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
