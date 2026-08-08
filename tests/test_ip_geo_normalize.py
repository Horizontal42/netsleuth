from __future__ import annotations

import pytest

from netcheck.ip_geo import (
    classify_ip_type,
    normalize_freeipapi,
    normalize_ip_api,
    normalize_ipinfo,
    normalize_ipwhois,
    normalize_ripestat_network_info,
    parse_cf_trace,
    provider_flags,
)


def test_ip_api_normalizes_to_the_common_shape(api_fixture):
    geo = normalize_ip_api(api_fixture("ip_api.json"))
    assert geo.ip == "203.0.113.44"
    assert geo.ip_version == 4
    assert geo.asn == "AS64500"
    assert geo.as_name == "Example Telecom"
    assert geo.org == "Example Telecom BV"
    assert geo.country == "Netherlands"
    assert geo.country_code == "NL"
    assert geo.city == "Amsterdam"
    assert geo.lat == 52.3759
    assert geo.lon == 4.8975
    assert geo.timezone == "Europe/Amsterdam"
    assert geo.reverse_dns == "host-203-0-113-44.example.net"
    assert geo.ip_type == "hosting"


def test_ip_api_failure_payload_yields_an_empty_geo_not_an_exception(api_fixture):
    geo = normalize_ip_api(api_fixture("ip_api_fail.json"))
    assert geo.asn is None
    assert geo.country is None
    assert geo.ip_type == "unknown"


def test_freeipapi_normalizes_and_prefixes_the_bare_asn(api_fixture):
    geo = normalize_freeipapi(api_fixture("freeipapi.json"))
    assert geo.ip == "203.0.113.44"
    assert geo.ip_version == 4
    assert geo.asn == "AS64500"
    assert geo.org == "Example Telecom BV"
    assert geo.country_code == "NL"
    assert geo.city == "Amsterdam"
    assert geo.ip_type == "residential"


def test_ipinfo_splits_the_org_field_into_asn_and_name(api_fixture):
    geo = normalize_ipinfo(api_fixture("ipinfo.json"))
    assert geo.asn == "AS64500"
    assert geo.as_name == "Example Telecom BV"
    assert geo.lat == 52.3759
    assert geo.lon == 4.8975
    assert geo.country_code == "NL"
    assert geo.reverse_dns == "host-203-0-113-44.example.net"


def test_ipinfo_without_a_loc_field_does_not_crash():
    geo = normalize_ipinfo({"ip": "203.0.113.44", "org": "AS64500 Example"})
    assert geo.lat is None
    assert geo.lon is None


def test_ipwhois_reads_the_nested_connection_and_timezone_objects(api_fixture):
    geo = normalize_ipwhois(api_fixture("ipwhois.json"))
    assert geo.asn == "AS64500"
    assert geo.as_name == "Example Telecom"
    assert geo.org == "Example Telecom BV"
    assert geo.timezone == "Europe/Amsterdam"
    assert geo.ip_version == 4
    assert geo.country_code == "NL"


def test_ripestat_network_info_gives_authoritative_asn_only(api_fixture):
    geo = normalize_ripestat_network_info(api_fixture("ripestat_network_info.json"))
    assert geo.asn == "AS64500"
    assert geo.city is None
    assert geo.sources == {"asn": "ripestat"}


def test_cf_trace_parses_every_key_and_the_vpn_relevant_flags(fixtures_dir):
    cf = parse_cf_trace((fixtures_dir / "api" / "cf_trace.txt").read_text(encoding="utf-8"))
    assert cf.ip == "203.0.113.44"
    assert cf.colo == "AMS"
    assert cf.loc == "NL"
    assert cf.warp == "off"
    assert cf.gateway == "off"
    assert cf.rbi == "off"
    assert cf.raw["tls"] == "TLSv1.3"


def test_cf_trace_tolerates_blank_lines_and_missing_keys():
    cf = parse_cf_trace("ip=1.2.3.4\n\nnot-a-pair\ncolo=AMS\n")
    assert cf.ip == "1.2.3.4"
    assert cf.colo == "AMS"
    assert cf.warp is None


def test_provider_flags_reads_the_ip_api_booleans(api_fixture):
    assert provider_flags(api_fixture("ip_api.json")) == {
        "mobile": False,
        "proxy": False,
        "hosting": True,
    }


def test_provider_flags_of_a_failed_payload_is_empty(api_fixture):
    assert provider_flags(api_fixture("ip_api_fail.json")) == {}


@pytest.mark.parametrize(
    ("mobile", "proxy", "hosting", "known", "expected"),
    [
        (False, False, False, False, "unknown"),
        (False, False, False, True, "residential"),
        (True, False, False, True, "mobile"),
        (True, False, True, True, "mobile"),
        (False, True, False, True, "hosting"),
        (False, False, True, True, "hosting"),
    ],
)
def test_ip_type_classification(mobile, proxy, hosting, known, expected):
    assert classify_ip_type(mobile, proxy, hosting, known) == expected


from netcheck.models import IpGeo
from netcheck.ip_geo import dual_stack_mismatch, merge_geo


def test_merge_takes_the_first_non_empty_value_in_priority_order():
    merged = merge_geo(
        [
            ("cf-trace", IpGeo(ip="203.0.113.44")),
            ("ip-api", IpGeo(asn="AS64500", city="Amsterdam", country_code="NL")),
            ("ipwho.is", IpGeo(asn="AS64999", city="Rotterdam", timezone="Europe/Amsterdam")),
        ]
    )
    assert merged.ip == "203.0.113.44"
    assert merged.asn == "AS64500"
    assert merged.city == "Amsterdam"
    assert merged.timezone == "Europe/Amsterdam"


def test_merge_records_which_provider_supplied_each_field():
    merged = merge_geo(
        [
            ("cf-trace", IpGeo(ip="203.0.113.44")),
            ("ip-api", IpGeo(asn="AS64500")),
            ("ipwho.is", IpGeo(timezone="Europe/Amsterdam")),
        ]
    )
    assert merged.sources["ip"] == "cf-trace"
    assert merged.sources["asn"] == "ip-api"
    assert merged.sources["timezone"] == "ipwho.is"


def test_merge_prefers_a_known_ip_type_over_unknown():
    merged = merge_geo([("a", IpGeo(ip_type="unknown")), ("b", IpGeo(ip_type="mobile"))])
    assert merged.ip_type == "mobile"
    assert merged.sources["ip_type"] == "b"


def test_merge_of_nothing_is_an_empty_geo():
    merged = merge_geo([])
    assert merged.ip is None
    assert merged.ip_type == "unknown"
    assert merged.sources == {}


def test_merge_ignores_a_provider_that_returned_nothing():
    merged = merge_geo([("dead", IpGeo()), ("live", IpGeo(asn="AS64500"))])
    assert merged.asn == "AS64500"
    assert merged.sources["asn"] == "live"


def test_dual_stack_mismatch_is_reported_not_resolved():
    v4 = IpGeo(ip="203.0.113.44", asn="AS64500", country_code="NL")
    v6 = IpGeo(ip="2001:db8::1", asn="AS64777", country_code="DE")
    note = dual_stack_mismatch(v4, v6)
    assert note is not None
    assert "AS64500" in note
    assert "AS64777" in note


def test_dual_stack_agreement_produces_no_note():
    v4 = IpGeo(ip="203.0.113.44", asn="AS64500", country_code="NL")
    v6 = IpGeo(ip="2001:db8::1", asn="AS64500", country_code="NL")
    assert dual_stack_mismatch(v4, v6) is None


def test_dual_stack_comparison_needs_both_sides():
    assert dual_stack_mismatch(IpGeo(asn="AS64500"), None) is None
    assert dual_stack_mismatch(None, IpGeo(asn="AS64500")) is None
