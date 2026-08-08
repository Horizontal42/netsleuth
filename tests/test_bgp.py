from __future__ import annotations

import httpx
import pytest

from netcheck.bgp import (
    classify_stability,
    parse_announced_prefixes,
    parse_as_overview,
    parse_asn_neighbours,
    parse_bgp_updates,
    ripestat,
)
from netcheck.config import Providers
from netcheck.models import BgpEvent


def test_as_overview_extracts_holder_and_block(api_fixture):
    info = parse_as_overview(api_fixture("ripestat_as_overview.json"))
    assert info["holder"] == "EXAMPLE-AS Example Telecom BV"
    assert info["registry"] == "IANA 16-bit Autonomous System Number Block"


def test_as_overview_of_an_error_payload_is_empty():
    assert parse_as_overview({"status": "error", "data": {}}) == {
        "holder": None,
        "registry": None,
        "allocated_at": None,
    }


def test_neighbours_split_into_upstreams_peers_and_downstreams(api_fixture):
    upstreams, peers, downstreams = parse_asn_neighbours(api_fixture("ripestat_asn_neighbours.json"))
    assert upstreams == ["AS3356", "AS1299"]
    assert downstreams == ["AS6939", "AS64501"]
    assert peers == ["AS8075"]


def test_announced_prefixes_are_counted_by_family(api_fixture):
    prefixes, v4, v6 = parse_announced_prefixes(api_fixture("ripestat_announced_prefixes.json"))
    assert prefixes == ["203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"]
    assert v4 == 2
    assert v6 == 1


def test_announced_prefixes_of_an_empty_payload():
    assert parse_announced_prefixes({"data": {}}) == ([], 0, 0)


def test_bgp_updates_become_typed_events(api_fixture):
    events = parse_bgp_updates(api_fixture("ripestat_bgp_updates.json"))
    assert len(events) == 3
    assert events[0].type == "A"
    assert events[0].prefix == "203.0.113.0/24"
    assert events[0].path == [3356, 64500]
    assert events[1].type == "W"
    assert events[1].path == []


def test_stability_of_a_quiet_asn_is_stable():
    assert classify_stability([], days=14) == "stable"


def test_stability_of_a_flapping_asn_is_unstable():
    events = [BgpEvent(timestamp="2026-08-01T00:00:00", type="W", prefix="203.0.113.0/24") for _ in range(60)]
    assert classify_stability(events, days=14) == "unstable"


def test_stability_only_counts_withdrawals_not_announcements():
    events = [BgpEvent(timestamp="2026-08-01T00:00:00", type="A", prefix="203.0.113.0/24") for _ in range(200)]
    assert classify_stability(events, days=14) == "stable"


def test_stability_is_unknown_without_a_timeframe():
    assert classify_stability([BgpEvent(timestamp="x", type="W")], days=0) == "unknown"


async def test_ripestat_bounds_bulk_calls_with_max_rows_and_a_timeframe(httpx_mock):
    httpx_mock.add_response(json={"status": "ok", "data": {}})
    providers = Providers(ripestat_max_rows=25, ripestat_timeframe_days=7)
    async with httpx.AsyncClient() as client:
        await ripestat(client, providers, "bgp-updates", "AS64500")
    request = httpx_mock.get_request()
    assert request.url.params["resource"] == "AS64500"
    assert request.url.params["max_rows"] == "25"
    assert "starttime" in request.url.params
    assert request.url.path.endswith("/bgp-updates/data.json")


async def test_ripestat_does_not_bound_non_bulk_calls(httpx_mock):
    httpx_mock.add_response(json={"status": "ok", "data": {}})
    async with httpx.AsyncClient() as client:
        await ripestat(client, Providers(), "as-overview", "AS64500")
    request = httpx_mock.get_request()
    assert "max_rows" not in request.url.params
    assert "starttime" not in request.url.params
