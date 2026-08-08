from __future__ import annotations

from netcheck.reputation import NetsetIndex, parse_netset


def test_parse_netset_strips_comments_and_blank_lines(fixtures_dir):
    cidrs = parse_netset((fixtures_dir / "api" / "firehol_sample.netset").read_text(encoding="utf-8"))
    assert cidrs == [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "198.51.100.0/24",
        "203.0.113.44",
        "2001:db8::/32",
        "192.0.2.0/25",
    ]


def test_parse_netset_of_an_empty_file_is_empty():
    assert parse_netset("# only a comment\n\n") == []


def test_index_matches_an_ip_inside_a_listed_prefix():
    index = NetsetIndex()
    index.add("firehol_level1", ["198.51.100.0/24"])
    assert index.hits("198.51.100.7") == ["firehol_level1"]


def test_index_does_not_match_an_ip_outside_every_prefix():
    index = NetsetIndex()
    index.add("firehol_level1", ["198.51.100.0/24"])
    assert index.hits("203.0.113.7") == []


def test_index_matches_a_bare_host_entry():
    index = NetsetIndex()
    index.add("abusers", ["203.0.113.44"])
    assert index.hits("203.0.113.44") == ["abusers"]
    assert index.hits("203.0.113.45") == []


def test_index_reports_every_list_an_ip_appears_on():
    index = NetsetIndex()
    index.add("level1", ["198.51.100.0/24"])
    index.add("level2", ["198.51.100.0/25"])
    index.add("clean", ["203.0.113.0/24"])
    assert sorted(index.hits("198.51.100.7")) == ["level1", "level2"]


def test_index_handles_ipv6_separately_from_ipv4():
    index = NetsetIndex()
    index.add("v6list", ["2001:db8::/32"])
    index.add("v4list", ["203.0.113.0/24"])
    assert index.hits("2001:db8::1") == ["v6list"]
    assert index.hits("203.0.113.1") == ["v4list"]


def test_index_ignores_malformed_entries_instead_of_raising():
    index = NetsetIndex()
    index.add("junk", ["not-an-ip", "999.1.1.1/24", "198.51.100.0/24"])
    assert index.hits("198.51.100.7") == ["junk"]


def test_index_lookup_of_a_malformed_ip_is_empty_not_an_error():
    index = NetsetIndex()
    index.add("level1", ["198.51.100.0/24"])
    assert index.hits("not-an-ip") == []


def test_index_built_from_the_real_fixture_matches_the_expected_entries(fixtures_dir):
    index = NetsetIndex()
    index.add(
        "firehol_level1",
        parse_netset((fixtures_dir / "api" / "firehol_sample.netset").read_text(encoding="utf-8")),
    )
    assert index.hits("10.1.2.3") == ["firehol_level1"]
    assert index.hits("192.0.2.10") == ["firehol_level1"]
    assert index.hits("192.0.2.200") == []
