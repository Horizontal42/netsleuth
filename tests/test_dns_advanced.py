from __future__ import annotations

import httpx
import pytest

from netsleuth.models import ResolverProbe
from netsleuth.probes.dns_advanced import (
    compare_answers,
    detect_poisoning,
    detect_transparent_proxy,
    is_suspicious_answer,
    parse_doh_json,
    resolve_doh,
)


def test_parse_doh_json_extracts_addresses_from_a_successful_answer(api_fixture):
    payload = api_fixture("doh_cloudflare.json")
    assert parse_doh_json(payload) == ["104.16.132.229", "104.16.133.229"]


def test_parse_doh_json_returns_empty_list_on_nxdomain_status(api_fixture):
    payload = api_fixture("doh_nxdomain.json")
    assert parse_doh_json(payload) == []


def test_parse_doh_json_ignores_cname_and_keeps_only_a_records(api_fixture):
    payload = api_fixture("doh_cname_then_a.json")
    assert parse_doh_json(payload) == ["93.184.216.34"]


def test_parse_doh_json_returns_empty_list_on_empty_payload():
    assert parse_doh_json({}) == []


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("0.0.0.0", True),
        ("127.0.0.1", True),
        ("10.1.1.1", True),
        ("192.0.2.1", True),
        ("1.1.1.1", False),
        ("104.16.132.229", False),
    ],
)
def test_is_suspicious_answer_table(addr, expected):
    assert is_suspicious_answer(addr) is expected


def test_cdn_answers_that_merely_differ_are_not_flagged_as_poisoning():
    system_probe = ResolverProbe(name="system", kind="system", answers=["1.1.1.1"])
    doh_probes = [ResolverProbe(name="cloudflare", kind="doh", answers=["104.16.132.229"])]
    assert detect_poisoning(system_probe, doh_probes) is False


def test_a_bogon_system_answer_against_a_clean_doh_answer_is_flagged_as_poisoning():
    system_probe = ResolverProbe(name="system", kind="system", answers=["192.0.2.1"])
    doh_probes = [ResolverProbe(name="cloudflare", kind="doh", answers=["1.1.1.1"])]
    assert detect_poisoning(system_probe, doh_probes) is True


def test_detect_poisoning_is_false_when_both_sides_are_suspicious():
    system_probe = ResolverProbe(name="system", kind="system", answers=["0.0.0.0"])
    doh_probes = [ResolverProbe(name="cloudflare", kind="doh", answers=["127.0.0.1"])]
    assert detect_poisoning(system_probe, doh_probes) is False


def test_detect_poisoning_is_false_when_both_sides_are_empty():
    system_probe = ResolverProbe(name="system", kind="system", answers=[])
    doh_probes = [ResolverProbe(name="cloudflare", kind="doh", answers=[])]
    assert detect_poisoning(system_probe, doh_probes) is False


def test_compare_answers_reports_a_divergence_when_addresses_differ():
    system_probe = ResolverProbe(name="system", kind="system", query_name="cloudflare.com", answers=["1.1.1.1"])
    doh_probes = [
        ResolverProbe(name="cloudflare", kind="doh", query_name="cloudflare.com", answers=["104.16.132.229"])
    ]
    divergences = compare_answers(system_probe, doh_probes)
    assert len(divergences) == 1
    assert "cloudflare.com" in divergences[0]


def test_compare_answers_returns_empty_list_when_answers_match():
    system_probe = ResolverProbe(name="system", kind="system", query_name="cloudflare.com", answers=["1.1.1.1"])
    doh_probes = [ResolverProbe(name="cloudflare", kind="doh", query_name="cloudflare.com", answers=["1.1.1.1"])]
    assert compare_answers(system_probe, doh_probes) == []


def test_detect_transparent_proxy_true_when_bogus_ip_answers():
    bogus_probe = ResolverProbe(name="bogus", kind="system", answers=["93.184.216.34"], error=None)
    detected, detail = detect_transparent_proxy(bogus_probe)
    assert detected is True
    assert "detect" in detail.lower()


def test_detect_transparent_proxy_false_and_says_not_detected_not_absent_on_timeout():
    bogus_probe = ResolverProbe(name="bogus", kind="system", answers=[], error="timeout")
    detected, detail = detect_transparent_proxy(bogus_probe)
    assert detected is False
    lowered = detail.lower()
    assert "not detected" in lowered or "не обнаружен" in lowered
    assert "absent" not in lowered
    assert "none" not in lowered


@pytest.mark.asyncio
async def test_resolve_doh_populates_answers_from_a_mocked_response(httpx_mock, api_fixture):
    httpx_mock.add_response(
        url="https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A",
        json=api_fixture("doh_cloudflare.json"),
    )
    async with httpx.AsyncClient() as client:
        probe = await resolve_doh(client, "cloudflare", "https://cloudflare-dns.com/dns-query", "cloudflare.com", 4.0)
    assert probe.kind == "doh"
    assert probe.answers == ["104.16.132.229", "104.16.133.229"]
    assert probe.error is None


@pytest.mark.asyncio
async def test_resolve_doh_sets_error_on_http_error_status_without_raising(httpx_mock):
    httpx_mock.add_response(
        url="https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A",
        status_code=500,
    )
    async with httpx.AsyncClient() as client:
        probe = await resolve_doh(client, "cloudflare", "https://cloudflare-dns.com/dns-query", "cloudflare.com", 4.0)
    assert probe.error is not None
    assert probe.answers == []


@pytest.mark.asyncio
async def test_resolve_doh_sets_error_on_timeout_without_raising(httpx_mock):
    httpx_mock.add_exception(httpx.TimeoutException("timed out"))
    async with httpx.AsyncClient() as client:
        probe = await resolve_doh(client, "cloudflare", "https://cloudflare-dns.com/dns-query", "cloudflare.com", 4.0)
    assert probe.error is not None
    assert probe.answers == []
