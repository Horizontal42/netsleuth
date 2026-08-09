from __future__ import annotations

from netsleuth.reputation import (
    NetsetIndex,
    build_reputation,
    ReputationContext,
    captcha_risk,
    decode_dnsbl,
    normalize_internetdb,
    parse_netset,
    summarize_dnsbl,
)


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


def test_internetdb_normalizes_into_the_typed_result(api_fixture):
    result = normalize_internetdb(api_fixture("internetdb.json"))
    assert result.ip == "203.0.113.44"
    assert result.ports == [22, 80, 443, 7547]
    assert result.tags == ["cdn", "iot"]
    assert result.vulns == ["CVE-2024-1234"]


def test_internetdb_404_shape_becomes_an_empty_result():
    result = normalize_internetdb({"detail": "No information available"})
    assert result.ip is None
    assert result.ports == []


def test_captcha_risk_is_low_for_a_clean_residential_address():
    risk, rationale = captcha_risk([], [], "residential", None)
    assert risk == "low"
    assert rationale


def test_captcha_risk_is_medium_for_a_hosting_address_with_no_listings():
    risk, rationale = captcha_risk([], [], "hosting", None)
    assert risk == "medium"
    assert "hosting" in rationale.lower()


def test_captcha_risk_is_high_when_a_blocklist_matches():
    risk, rationale = captcha_risk(["firehol_level1"], [], "residential", None)
    assert risk == "high"
    assert "firehol_level1" in rationale


def test_captcha_risk_is_high_on_a_real_dnsbl_listing():
    hits, _ = summarize_dnsbl([decode_dnsbl("zen.spamhaus.org", ["127.0.0.2"])])
    risk, rationale = captcha_risk([], hits, "residential", None)
    assert risk == "high"
    assert "zen.spamhaus.org" in rationale


def test_captcha_risk_escalates_on_a_high_abuseipdb_score():
    assert captcha_risk([], [], "residential", 90)[0] == "high"
    assert captcha_risk([], [], "residential", 30)[0] == "medium"
    assert captcha_risk([], [], "residential", 5)[0] == "low"


def test_build_reputation_marks_the_query_as_blocked_without_inventing_hits(api_fixture):
    rep = build_reputation(
        ReputationContext(
            internetdb=normalize_internetdb(api_fixture("internetdb.json")),
            firehol_hits=[],
            dnsbl_outcomes=[decode_dnsbl("zen.spamhaus.org", ["127.255.255.254"])],
            ip_type="residential",
            abuseipdb_score=None,
            abuseipdb_reports=None,
        )
    )
    assert rep.dnsbl_hits == []
    assert rep.dnsbl_query_blocked is True
    assert rep.captcha_risk == "low"


def test_build_reputation_without_dnsbl_leaves_the_field_none(api_fixture):
    rep = build_reputation(
        ReputationContext(
            internetdb=normalize_internetdb(api_fixture("internetdb.json")),
            firehol_hits=["firehol_level1"],
            dnsbl_outcomes=None,
            ip_type="residential",
            abuseipdb_score=None,
            abuseipdb_reports=None,
        )
    )
    assert rep.dnsbl_hits is None
    assert rep.dnsbl_query_blocked is False
    assert rep.captcha_risk == "high"


_CYRILLIC = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")


def has_cyrillic(text: str) -> bool:
    return any(ch in _CYRILLIC for ch in text.lower())


def test_build_reputation_rationale_ru_is_populated_and_cyrillic_for_every_reason(api_fixture):
    cases = [
        dict(firehol_hits=["firehol_level1"], dnsbl_outcomes=None, ip_type="residential", abuseipdb_score=None),
        dict(
            firehol_hits=[],
            dnsbl_outcomes=[decode_dnsbl("zen.spamhaus.org", ["127.0.0.2"])],
            ip_type="residential",
            abuseipdb_score=None,
        ),
        dict(firehol_hits=[], dnsbl_outcomes=None, ip_type="residential", abuseipdb_score=90),
        dict(firehol_hits=[], dnsbl_outcomes=None, ip_type="residential", abuseipdb_score=30),
        dict(firehol_hits=[], dnsbl_outcomes=None, ip_type="hosting", abuseipdb_score=None),
        dict(firehol_hits=[], dnsbl_outcomes=None, ip_type="residential", abuseipdb_score=None),
    ]
    for case in cases:
        rep = build_reputation(
            ReputationContext(
                internetdb=normalize_internetdb(api_fixture("internetdb.json")),
                firehol_hits=case["firehol_hits"],
                dnsbl_outcomes=case["dnsbl_outcomes"],
                ip_type=case["ip_type"],
                abuseipdb_score=case["abuseipdb_score"],
                abuseipdb_reports=None,
            )
        )
        assert rep.rationale
        assert rep.rationale_ru
        assert has_cyrillic(rep.rationale_ru)


def test_captcha_risk_public_signature_still_returns_a_two_tuple():
    result = captcha_risk([], [], "residential", None)
    assert len(result) == 2
    risk, rationale = result
    assert risk == "low"
    assert rationale
