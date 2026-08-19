from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, patch

import dns.asyncresolver
import dns.exception
import httpx
import pytest

from netsleuth.config import Providers
from netsleuth.reputation import (
    DnsblOutcome,
    NetsetIndex,
    ReputationContext,
    build_reputation,
    captcha_risk,
    decode_dnsbl,
    fetch_abuseipdb,
    fetch_internetdb,
    normalize_internetdb,
    parse_netset,
    query_dnsbl,
    refresh_netsets,
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


@pytest.mark.asyncio
async def test_query_dnsbl_happy_path():
    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_answer = AsyncMock()
        mock_record1 = AsyncMock()
        mock_record1.address = "127.0.0.2"
        mock_record2 = AsyncMock()
        mock_record2.address = "127.0.0.3"

        # answer is iterable and returns our mocked records
        mock_answer.__iter__.return_value = iter([mock_record1, mock_record2])
        mock_resolve.return_value = mock_answer

        outcomes = await query_dnsbl("192.168.1.1", ["zen.spamhaus.org"], 5.0)

        assert len(outcomes) == 1
        assert outcomes[0].zone == "zen.spamhaus.org"
        assert outcomes[0].listed is True
        assert outcomes[0].codes == ["127.0.0.2", "127.0.0.3"]

        # Verify it reversed the IP correctly for the query
        mock_resolve.assert_called_once_with("1.1.168.192.zen.spamhaus.org", "A")

@pytest.mark.asyncio
async def test_query_dnsbl_dns_exception():
    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = dns.exception.DNSException("Test error")

        outcomes = await query_dnsbl("192.168.1.1", ["zen.spamhaus.org"], 5.0)

        assert len(outcomes) == 1
        assert outcomes[0].zone == "zen.spamhaus.org"
        assert outcomes[0].listed is False
        assert outcomes[0].codes == []

@pytest.mark.asyncio
async def test_query_dnsbl_multiple_zones():
    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        def resolve_side_effect(qname, rdtype):
            if "zone1" in qname:
                mock_answer = AsyncMock()
                mock_record = AsyncMock()
                mock_record.address = "127.0.0.2"
                mock_answer.__iter__.return_value = iter([mock_record])
                return mock_answer
            elif "zone2" in qname:
                raise dns.exception.DNSException("NXDOMAIN")

        mock_resolve.side_effect = resolve_side_effect

        outcomes = await query_dnsbl("192.168.1.1", ["zone1.com", "zone2.com"], 5.0)

        # Sort outcomes to ensure test consistency as asyncio.gather does not guarantee order
        outcomes.sort(key=lambda o: o.zone)

        assert len(outcomes) == 2
        assert outcomes[0].zone == "zone1.com"
        assert outcomes[0].listed is True
        assert outcomes[0].codes == ["127.0.0.2"]

        assert outcomes[1].zone == "zone2.com"
        assert outcomes[1].listed is False
        assert outcomes[1].codes == []


@pytest.fixture
def providers():
    return Providers(
        firehol_netsets=[
            "http://example.com/firehol_level1.netset",
            "http://example.com/firehol_level2.netset"
        ]
    )

async def test_refresh_netsets_setup_dir(httpx_mock, tmp_path, providers):
    httpx_mock.add_response(url="http://example.com/firehol_level1.netset", text="192.0.2.0/24\n")
    httpx_mock.add_response(url="http://example.com/firehol_level2.netset", text="198.51.100.0/24\n")

    import pathlib

    original_mkdir = pathlib.Path.mkdir

    def mocked_mkdir(self, *args, **kwargs):
        return original_mkdir(self, *args, **kwargs)

    with patch("pathlib.Path.mkdir", side_effect=mocked_mkdir, autospec=True) as mock_mkdir:
        async with httpx.AsyncClient() as client:
            await refresh_netsets(client, providers, tmp_path)

        mock_mkdir.assert_any_call(tmp_path / "firehol", parents=True, exist_ok=True)


async def test_refresh_netsets_downloads_new_lists_and_caches_them(httpx_mock, tmp_path, providers):
    httpx_mock.add_response(url="http://example.com/firehol_level1.netset", text="192.0.2.0/24\n")
    httpx_mock.add_response(url="http://example.com/firehol_level2.netset", text="198.51.100.0/24\n")

    async with httpx.AsyncClient() as client:
        index = await refresh_netsets(client, providers, tmp_path)

    assert index.hits("192.0.2.1") == ["firehol_level1"]
    assert index.hits("198.51.100.1") == ["firehol_level2"]

    cache_dir = tmp_path / "firehol"
    assert (cache_dir / "firehol_level1.netset").exists()
    assert (cache_dir / "firehol_level1.netset").read_text() == "192.0.2.0/24\n"
    assert (cache_dir / "firehol_level2.netset").exists()

async def test_refresh_netsets_uses_fresh_cache_without_downloading(httpx_mock, tmp_path, providers):
    cache_dir = tmp_path / "firehol"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "firehol_level1.netset").write_text("192.0.2.0/24\n")
    (cache_dir / "firehol_level2.netset").write_text("198.51.100.0/24\n")

    # Set mtime to now so it's fresh
    now = time.time()
    os.utime(cache_dir / "firehol_level1.netset", (now, now))
    os.utime(cache_dir / "firehol_level2.netset", (now, now))

    # httpx_mock shouldn't receive any requests
    async with httpx.AsyncClient() as client:
        index = await refresh_netsets(client, providers, tmp_path)

    assert index.hits("192.0.2.1") == ["firehol_level1"]

async def test_refresh_netsets_falls_back_to_stale_cache_on_http_error(httpx_mock, tmp_path, providers):
    cache_dir = tmp_path / "firehol"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "firehol_level1.netset").write_text("192.0.2.0/24\n")
    (cache_dir / "firehol_level2.netset").write_text("198.51.100.0/24\n")

    # Make cache stale
    stale_time = time.time() - (providers.firehol_refresh_hours * 3600 + 100)
    os.utime(cache_dir / "firehol_level1.netset", (stale_time, stale_time))
    os.utime(cache_dir / "firehol_level2.netset", (stale_time, stale_time))

    # Fail the download
    httpx_mock.add_response(url="http://example.com/firehol_level1.netset", status_code=500)
    httpx_mock.add_response(url="http://example.com/firehol_level2.netset", status_code=500)

    async with httpx.AsyncClient() as client:
        index = await refresh_netsets(client, providers, tmp_path)

    # Should still load the data from cache
    assert index.hits("192.0.2.1") == ["firehol_level1"]
    assert index.hits("198.51.100.1") == ["firehol_level2"]

async def test_refresh_netsets_skips_list_on_http_error_if_no_cache_exists(httpx_mock, tmp_path, providers):
    httpx_mock.add_response(url="http://example.com/firehol_level1.netset", text="192.0.2.0/24\n")
    httpx_mock.add_response(url="http://example.com/firehol_level2.netset", status_code=404)

    async with httpx.AsyncClient() as client:
        index = await refresh_netsets(client, providers, tmp_path)

    assert index.hits("192.0.2.1") == ["firehol_level1"]
    assert index.hits("198.51.100.1") == []

    cache_dir = tmp_path / "firehol"
    assert (cache_dir / "firehol_level1.netset").exists()
    assert not (cache_dir / "firehol_level2.netset").exists()


def test_summarize_dnsbl_empty():
    hits, blocked = summarize_dnsbl([])
    assert hits == []
    assert blocked is False


def test_summarize_dnsbl_all_listed():
    outcomes = [
        DnsblOutcome(zone="zone1", listed=True, codes=["127.0.0.2"]),
        DnsblOutcome(zone="zone2", listed=True, codes=["127.0.0.3"]),
    ]
    hits, blocked = summarize_dnsbl(outcomes)
    assert len(hits) == 2
    assert hits[0].zone == "zone1"
    assert hits[0].codes == ["127.0.0.2"]
    assert hits[0].meaning == "listed"
    assert hits[1].zone == "zone2"
    assert hits[1].codes == ["127.0.0.3"]
    assert hits[1].meaning == "listed"
    assert blocked is False


def test_summarize_dnsbl_some_blocked():
    outcomes = [
        DnsblOutcome(zone="zone1", listed=True, codes=["127.0.0.2"]),
        DnsblOutcome(zone="zone2", listed=False, codes=[], unavailable_reason="rate_limited"),
        DnsblOutcome(zone="zone3", listed=False, codes=[]),
    ]
    hits, blocked = summarize_dnsbl(outcomes)
    assert len(hits) == 1
    assert hits[0].zone == "zone1"
    assert hits[0].codes == ["127.0.0.2"]
    assert blocked is True


async def test_fetch_abuseipdb_success(httpx_mock):
    httpx_mock.add_response(
        url="https://api.abuseipdb.com/api/v2/check?ipAddress=192.0.2.1&maxAgeInDays=90",
        json={"data": {"ipAddress": "192.0.2.1", "abuseConfidenceScore": 50}},
    )
    providers = Providers()
    async with httpx.AsyncClient() as client:
        result = await fetch_abuseipdb(client, providers, "192.0.2.1", "secret_key")

    assert result == {"data": {"ipAddress": "192.0.2.1", "abuseConfidenceScore": 50}}

    request = httpx_mock.get_request()
    assert request.headers["Key"] == "secret_key"
    assert request.headers["Accept"] == "application/json"


async def test_fetch_abuseipdb_raises_on_http_error(httpx_mock):
    httpx_mock.add_response(
        url="https://api.abuseipdb.com/api/v2/check?ipAddress=192.0.2.1&maxAgeInDays=90",
        status_code=403,
    )
    providers = Providers()
    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_abuseipdb(client, providers, "192.0.2.1", "secret_key")


async def test_fetch_internetdb_returns_json_on_success(httpx_mock):
    providers = Providers()
    ip = "1.2.3.4"
    mock_response = {"ip": ip, "ports": [80, 443]}
    httpx_mock.add_response(
        url=f"{providers.internetdb_url}{ip}",
        json=mock_response,
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_internetdb(client, providers, ip)

    assert result == mock_response

async def test_fetch_internetdb_returns_no_info_on_404(httpx_mock):
    providers = Providers()
    ip = "1.2.3.4"
    httpx_mock.add_response(
        url=f"{providers.internetdb_url}{ip}",
        status_code=404,
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_internetdb(client, providers, ip)

    assert result == {"detail": "No information available"}

async def test_fetch_internetdb_raises_on_other_errors(httpx_mock):
    providers = Providers()
    ip = "1.2.3.4"
    httpx_mock.add_response(
        url=f"{providers.internetdb_url}{ip}",
        status_code=500,
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_internetdb(client, providers, ip)
