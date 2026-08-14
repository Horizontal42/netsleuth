from __future__ import annotations

from pathlib import Path

from netsleuth.history import find_previous, latest_key, matching_reports, report_key


def test_report_key_prefers_the_explicit_target():
    assert report_key({"target": "AS64500"}, {}) == "AS64500"


def test_report_key_falls_back_to_egress_asn():
    report = {"ip_geo": {"data": {"egress_v4": {"asn": "AS64500"}}}}
    assert report_key({}, report) == "AS64500"


def test_matching_reports_orders_newest_first_across_days():
    paths = [
        Path("2026/01/01/report_AS64500_00-00-00Z.json"),
        Path("2026/01/03/report_AS64500_00-00-00Z.json"),
        Path("2026/01/02/report_AS64500_00-00-00Z.json"),
    ]
    assert matching_reports(paths, "AS64500") == [
        Path("2026/01/03/report_AS64500_00-00-00Z.json"),
        Path("2026/01/02/report_AS64500_00-00-00Z.json"),
        Path("2026/01/01/report_AS64500_00-00-00Z.json"),
    ]


def test_matching_reports_orders_newest_first_within_a_day():
    paths = [
        Path("2026/01/01/report_AS64500_09-00-00Z.json"),
        Path("2026/01/01/report_AS64500_23-00-00Z.json"),
        Path("2026/01/01/report_AS64500_14-00-00Z.json"),
    ]
    assert matching_reports(paths, "AS64500") == [
        Path("2026/01/01/report_AS64500_23-00-00Z.json"),
        Path("2026/01/01/report_AS64500_14-00-00Z.json"),
        Path("2026/01/01/report_AS64500_09-00-00Z.json"),
    ]


def test_matching_reports_excludes_the_current_file():
    paths = [
        Path("2026/01/01/report_AS64500_00-00-00Z.json"),
        Path("2026/01/02/report_AS64500_09-00-00Z.json"),
    ]
    assert matching_reports(paths, "AS64500", exclude="report_AS64500_09-00-00Z.json") == [
        Path("2026/01/01/report_AS64500_00-00-00Z.json")
    ]


def test_matching_reports_does_not_cross_contaminate_different_keys():
    paths = [Path("2026/01/01/report_AS1_00-00-00Z.json"), Path("2026/01/01/report_AS13335_00-00-00Z.json")]
    assert matching_reports(paths, "AS1") == [Path("2026/01/01/report_AS1_00-00-00Z.json")]


def test_matching_reports_ignores_non_json_files():
    paths = [Path("2026/01/01/report_AS64500_00-00-00Z.md"), Path("2026/01/01/report_AS64500_00-00-00Z.json")]
    assert matching_reports(paths, "AS64500") == [Path("2026/01/01/report_AS64500_00-00-00Z.json")]


def test_find_previous_on_an_empty_directory(tmp_path):
    assert find_previous(tmp_path, "AS64500") == []


def test_find_previous_on_a_nonexistent_directory(tmp_path):
    assert find_previous(tmp_path / "nope", "AS64500") == []


def test_find_previous_walks_the_year_month_day_tree(tmp_path):
    for date_dir, ts in (("2026/01/01", "00-00-00Z"), ("2026/01/02", "00-00-00Z"), ("2026/01/03", "00-00-00Z")):
        d = tmp_path / date_dir
        d.mkdir(parents=True)
        (d / f"report_AS64500_{ts}.json").write_text("{}", encoding="utf-8")
    result = find_previous(tmp_path, "AS64500", limit=2)
    assert len(result) == 2
    assert result[0].parent.name == "03"


def test_latest_key_picks_the_newest_report_across_any_key_and_day(tmp_path):
    (tmp_path / "2026/01/01").mkdir(parents=True)
    (tmp_path / "2026/01/01/report_AS1_00-00-00Z.json").write_text("{}", encoding="utf-8")
    (tmp_path / "2026/01/02").mkdir(parents=True)
    (tmp_path / "2026/01/02/report_AS2_00-00-00Z.json").write_text("{}", encoding="utf-8")
    assert latest_key(tmp_path) == "AS2"


def test_latest_key_on_an_empty_directory(tmp_path):
    assert latest_key(tmp_path) is None
