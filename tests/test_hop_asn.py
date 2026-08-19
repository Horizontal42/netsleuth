from __future__ import annotations

import pytest

from netsleuth.interpret import path_asn_findings
from netsleuth.models import TraceHop, TraceResult
from netsleuth.probes.hop_asn import cymru_query_name, enrich_hops, parse_cymru_asname

ORIGIN_ZONE = "origin.asn.cymru.com"
ORIGIN6_ZONE = "origin6.asn.cymru.com"


def test_cymru_query_name_reverses_ipv4_octets():
    assert cymru_query_name("1.2.3.4", ORIGIN_ZONE, ORIGIN6_ZONE) == f"4.3.2.1.{ORIGIN_ZONE}"


def test_cymru_query_name_reverses_ipv6_nibbles_against_a_hand_expanded_literal():
    # 2001:db8::1 expands to 2001:0db8:0000:...:0001 -> 32 hex nibbles, reversed and
    # dot-joined. Verified independently via `ipaddress` before hardcoding here.
    expected = "1" + ".0" * 23 + ".8.b.d.0.1.0.0.2"
    assert cymru_query_name("2001:db8::1", ORIGIN_ZONE, ORIGIN6_ZONE) == f"{expected}.{ORIGIN6_ZONE}"


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.1", "192.168.1.1", "100.64.0.1", "127.0.0.1", "fe80::1", None, "*"],
)
def test_cymru_query_name_returns_none_for_non_routable_or_invalid_input(ip):
    assert cymru_query_name(ip, ORIGIN_ZONE, ORIGIN6_ZONE) is None


def test_parse_cymru_asname_extracts_name_and_country():
    name, country = parse_cymru_asname("15169 | US | arin | 2000-03-30 | GOOGLE, US")
    assert name == "GOOGLE, US"
    assert country == "US"


def test_parse_cymru_asname_handles_a_malformed_record():
    assert parse_cymru_asname("garbage without pipes") == (None, None)


def test_parse_cymru_asname_handles_an_empty_record():
    assert parse_cymru_asname("") == (None, None)


@pytest.mark.asyncio
async def test_enrich_hops_dedupes_repeated_ips_and_skips_none_ips(monkeypatch):
    calls: list[str] = []

    async def fake_lookup_hop(ip, **kwargs):
        calls.append(ip)
        return {"asn": "AS15169", "as_name": "GOOGLE", "country": "US"}

    monkeypatch.setattr("netsleuth.probes.hop_asn.lookup_hop", fake_lookup_hop)

    hop_a = TraceHop(ttl=1, ip="8.8.8.8")
    hop_b = TraceHop(ttl=2, ip="8.8.8.8")
    hop_c = TraceHop(ttl=3, ip=None)
    trace = TraceResult(target="8.8.8.8", hops=[hop_a, hop_b, hop_c])

    await enrich_hops(
        [trace], origin_zone=ORIGIN_ZONE, origin6_zone=ORIGIN6_ZONE, asn_zone="asn.cymru.com", timeout=1.0
    )

    assert calls == ["8.8.8.8"]
    assert hop_a.asn == hop_b.asn == "AS15169"
    assert hop_c.asn is None


@pytest.mark.asyncio
async def test_enrich_hops_fills_reverse_dns_only_when_absent(monkeypatch):
    async def fake_lookup_hop(ip, **kwargs):
        return {"reverse_dns": "router.example.net"}

    monkeypatch.setattr("netsleuth.probes.hop_asn.lookup_hop", fake_lookup_hop)

    hop_with_rdns = TraceHop(ttl=1, ip="1.1.1.1", reverse_dns="already.set")
    hop_without_rdns = TraceHop(ttl=2, ip="9.9.9.9")
    trace = TraceResult(target="1.1.1.1", hops=[hop_with_rdns, hop_without_rdns])

    await enrich_hops(
        [trace], origin_zone=ORIGIN_ZONE, origin6_zone=ORIGIN6_ZONE, asn_zone="asn.cymru.com", timeout=1.0
    )

    assert hop_with_rdns.reverse_dns == "already.set"
    assert hop_without_rdns.reverse_dns == "router.example.net"


def _trace_with_countries(*countries: str | None) -> TraceResult:
    hops = [TraceHop(ttl=i + 1, ip=f"1.1.1.{i}", country=c) for i, c in enumerate(countries)]
    return TraceResult(target="1.1.1.1", hops=hops)


def test_path_asn_findings_fires_on_two_consecutive_foreign_hops():
    trace = _trace_with_countries("RU", "DE", "DE", "US")
    findings = path_asn_findings(trace, "RU")
    assert [f.id for f in findings] == ["path.detour_country"]
    assert "DE" in findings[0].value


def test_path_asn_findings_silent_on_a_single_foreign_hop():
    trace = _trace_with_countries("RU", "DE", "US")
    assert path_asn_findings(trace, "RU") == []


def test_path_asn_findings_silent_when_country_is_unknown_throughout():
    trace = _trace_with_countries(None, None, None)
    assert path_asn_findings(trace, "RU") == []
