from __future__ import annotations

from netsleuth.history import find_previous, latest_key, matching_reports, report_key


def test_report_key_prefers_the_explicit_target():
    assert report_key({"target": "AS64500"}, {}) == "AS64500"


def test_report_key_falls_back_to_egress_asn():
    report = {"ip_geo": {"data": {"egress_v4": {"asn": "AS64500"}}}}
    assert report_key({}, report) == "AS64500"


def test_matching_reports_orders_newest_first():
    names = [
        "report_AS64500_20260101T000000Z.json",
        "report_AS64500_20260103T000000Z.json",
        "report_AS64500_20260102T000000Z.json",
    ]
    assert matching_reports(names, "AS64500") == [
        "report_AS64500_20260103T000000Z.json",
        "report_AS64500_20260102T000000Z.json",
        "report_AS64500_20260101T000000Z.json",
    ]


def test_matching_reports_excludes_the_current_file():
    names = ["report_AS64500_20260101T000000Z.json", "report_AS64500_20260102T000000Z.json"]
    assert matching_reports(names, "AS64500", exclude="report_AS64500_20260102T000000Z.json") == [
        "report_AS64500_20260101T000000Z.json"
    ]


def test_matching_reports_does_not_cross_contaminate_different_keys():
    names = ["report_AS1_20260101T000000Z.json", "report_AS13335_20260101T000000Z.json"]
    assert matching_reports(names, "AS1") == ["report_AS1_20260101T000000Z.json"]


def test_matching_reports_ignores_non_json_files():
    names = ["report_AS64500_20260101T000000Z.md", "report_AS64500_20260101T000000Z.json"]
    assert matching_reports(names, "AS64500") == ["report_AS64500_20260101T000000Z.json"]


def test_find_previous_on_an_empty_directory(tmp_path):
    assert find_previous(tmp_path, "AS64500") == []


def test_find_previous_on_a_nonexistent_directory(tmp_path):
    assert find_previous(tmp_path / "nope", "AS64500") == []


def test_find_previous_respects_limit(tmp_path):
    for ts in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
        (tmp_path / f"report_AS64500_{ts}.json").write_text("{}", encoding="utf-8")
    result = find_previous(tmp_path, "AS64500", limit=2)
    assert len(result) == 2
    assert result[0].name.endswith("20260103T000000Z.json")


def test_latest_key_picks_the_newest_report_across_any_key(tmp_path):
    (tmp_path / "report_AS1_20260101T000000Z.json").write_text("{}", encoding="utf-8")
    (tmp_path / "report_AS2_20260102T000000Z.json").write_text("{}", encoding="utf-8")
    assert latest_key(tmp_path) == "AS2"


def test_latest_key_on_an_empty_directory(tmp_path):
    assert latest_key(tmp_path) is None
