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
