from __future__ import annotations

import httpx
import pytest

from netsleuth.bgp import (
    classify_stability,
    parse_announced_prefixes,
    parse_as_overview,
    parse_asn_neighbours,
    parse_bgp_updates,
    ripestat,
)
from netsleuth.config import Providers
from netsleuth.models import BgpEvent


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


import json
from pathlib import Path

from netsleuth.bgp import (
    cached_json,
    parse_asrank,
    parse_cymru_origin,
    parse_peeringdb_net,
    parse_peeringdb_netixlan,
)


def test_asrank_gives_rank_and_customer_cone(api_fixture):
    rank, cone_asns, cone_prefixes = parse_asrank(api_fixture("asrank.json"))
    assert rank == 1842
    assert cone_asns == 37
    assert cone_prefixes == 412


def test_asrank_of_an_unknown_asn_is_all_none():
    assert parse_asrank({"data": {"asn": None}}) == (None, None, None)


def test_cymru_origin_txt_is_split_into_fields():
    record = "64500 | 203.0.113.0/24 | NL | ripencc | 2001-05-21"
    assert parse_cymru_origin(record) == {
        "asn": "AS64500",
        "prefix": "203.0.113.0/24",
        "country": "NL",
        "registry": "ripencc",
        "allocated_at": "2001-05-21",
    }


def test_cymru_origin_with_multiple_origin_asns_takes_the_first():
    record = "64500 64501 | 203.0.113.0/24 | NL | ripencc | 2001-05-21"
    assert parse_cymru_origin(record)["asn"] == "AS64500"


def test_cymru_origin_of_garbage_is_empty():
    assert parse_cymru_origin("no such name") == {}


def test_peeringdb_net_gives_info_type_traffic_and_id(api_fixture):
    info_type, traffic, net_id = parse_peeringdb_net(api_fixture("peeringdb_net.json"))
    assert info_type == "Cable/DSL/ISP"
    assert traffic == "100-200Gbps"
    assert net_id == 4242


def test_peeringdb_net_of_an_unlisted_asn_is_all_none():
    assert parse_peeringdb_net({"data": []}) == (None, None, None)


def test_peeringdb_netixlan_lists_only_operational_exchanges(api_fixture):
    ixps = parse_peeringdb_netixlan(api_fixture("peeringdb_netixlan.json"))
    assert [i.name for i in ixps] == ["AMS-IX", "DE-CIX Frankfurt"]
    assert ixps[0].country == "NL"
    assert ixps[1].speed_mbps == 200000


async def test_cached_json_writes_then_reuses_the_cache(tmp_path: Path):
    calls = []

    async def fetch() -> dict:
        calls.append(1)
        return {"value": len(calls)}

    first = await cached_json(tmp_path, "peeringdb-net-64500", ttl_hours=24, fetch=fetch)
    second = await cached_json(tmp_path, "peeringdb-net-64500", ttl_hours=24, fetch=fetch)
    assert first == {"value": 1}
    assert second == {"value": 1}
    assert len(calls) == 1
    assert json.loads((tmp_path / "peeringdb-net-64500.json").read_text(encoding="utf-8"))["value"] == 1


async def test_cached_json_refetches_once_the_entry_expires(tmp_path: Path):
    calls = []

    async def fetch() -> dict:
        calls.append(1)
        return {"value": len(calls)}

    await cached_json(tmp_path, "k", ttl_hours=24, fetch=fetch)
    result = await cached_json(tmp_path, "k", ttl_hours=0, fetch=fetch)
    assert result == {"value": 2}
    assert len(calls) == 2


async def test_cached_json_refetches_when_mtime_reads_ahead_of_now(tmp_path: Path):
    import os

    calls = []

    async def fetch() -> dict:
        calls.append(1)
        return {"value": len(calls)}

    await cached_json(tmp_path, "k", ttl_hours=24, fetch=fetch)
    future = (tmp_path / "k.json").stat().st_mtime + 5
    os.utime(tmp_path / "k.json", (future, future))
    result = await cached_json(tmp_path, "k", ttl_hours=0, fetch=fetch)
    assert result == {"value": 2}
    assert len(calls) == 2


async def test_cached_json_survives_a_corrupt_cache_file(tmp_path: Path):
    (tmp_path / "k.json").write_text("{not json", encoding="utf-8")

    async def fetch() -> dict:
        return {"value": "fresh"}

    assert await cached_json(tmp_path, "k", ttl_hours=24, fetch=fetch) == {"value": "fresh"}


from netsleuth.bgp import build_bgp_intel


def test_build_bgp_intel_merges_every_source(api_fixture):
    intel = build_bgp_intel(
        asn="AS64500",
        overview=api_fixture("ripestat_as_overview.json"),
        neighbours=api_fixture("ripestat_asn_neighbours.json"),
        prefixes=api_fixture("ripestat_announced_prefixes.json"),
        updates=api_fixture("ripestat_bgp_updates.json"),
        asrank=api_fixture("asrank.json"),
        pdb_net=api_fixture("peeringdb_net.json"),
        pdb_ixlan=api_fixture("peeringdb_netixlan.json"),
        timeframe_days=14,
    )
    assert intel.asn == "AS64500"
    assert intel.holder == "EXAMPLE-AS Example Telecom BV"
    assert intel.upstreams == ["AS3356", "AS1299"]
    assert intel.prefix_count_v4 == 2
    assert intel.prefix_count_v6 == 1
    assert intel.stability == "stable"
    assert intel.asrank == 1842
    assert intel.cone_asns == 37
    assert intel.pdb_info_type == "Cable/DSL/ISP"
    assert [i.name for i in intel.ixps] == ["AMS-IX", "DE-CIX Frankfurt"]
    assert len(intel.flaps) == 3


def test_build_bgp_intel_tolerates_every_optional_source_being_absent(api_fixture):
    intel = build_bgp_intel(
        asn="AS64500",
        overview=api_fixture("ripestat_as_overview.json"),
        neighbours={},
        prefixes={},
        updates={},
        asrank=None,
        pdb_net=None,
        pdb_ixlan=None,
        timeframe_days=14,
    )
    assert intel.asn == "AS64500"
    assert intel.upstreams == []
    assert intel.asrank is None
    assert intel.pdb_info_type is None
    assert intel.ixps == []
    assert intel.stability == "stable"
