from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from netsleuth.models import AnycastHop, PathDiversity
from netsleuth.probes.bgp_path import (
    build_path_diversity,
    colo_location,
    detect_international_loop,
    parse_cf_ray,
    probe_edge,
)

_CYRILLIC = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")


def has_cyrillic(text: str) -> bool:
    return any(ch in _CYRILLIC for ch in (text or "").lower())


def test_parse_cf_ray_extracts_colo_code():
    assert parse_cf_ray("9a1b2c3d4e5f6789-DME") == "DME"


def test_parse_cf_ray_normalizes_lowercase():
    assert parse_cf_ray("9a1b2c3d4e5f6789-dme") == "DME"


def test_parse_cf_ray_none_input():
    assert parse_cf_ray(None) is None


def test_parse_cf_ray_empty_string():
    assert parse_cf_ray("") is None


def test_parse_cf_ray_no_dash():
    assert parse_cf_ray("nodash") is None


def test_parse_cf_ray_trailing_dash_empty_suffix():
    assert parse_cf_ray("trailing-") is None


def test_colo_location_known_code():
    city, country = colo_location("DME")
    assert country == "RU"
    assert city


def test_colo_location_unknown_code():
    assert colo_location("ZZZ") == (None, None)


def test_colo_location_none():
    assert colo_location(None) == (None, None)


def test_detect_international_loop_true_when_edge_diverges():
    assert detect_international_loop("RU", "RU", "DE") == (True, ["DE"])


def test_detect_international_loop_false_when_edge_matches_client():
    assert detect_international_loop("RU", "RU", "RU") == (False, [])


def test_detect_international_loop_false_when_edge_unknown():
    assert detect_international_loop("RU", "RU", None) == (False, [])


def test_detect_international_loop_false_when_client_country_missing():
    assert detect_international_loop(None, "RU", "DE") == (False, [])


def test_build_path_diversity_with_looping_hop():
    hop = AnycastHop(target="example.com", ip_country="RU", edge_country="DE", source="cf_ray")
    diversity = build_path_diversity("RU", [hop])
    assert diversity.international_loop is True
    assert diversity.detour_countries
    assert has_cyrillic(diversity.note_ru)


def test_build_path_diversity_with_empty_hops_is_default():
    assert build_path_diversity("RU", []) == PathDiversity(client_country="RU", hops=[])


def test_anycast_hop_rejects_unknown_source():
    with pytest.raises(ValueError):
        AnycastHop(target="x", source="bogus")


@pytest.mark.asyncio
async def test_probe_edge_uses_cf_ray_header(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://example.com/cdn-cgi/trace",
        headers={"cf-ray": "abc123-FRA"},
        text="ip=1.2.3.4\ncolo=FRA\n",
    )

    async with httpx.AsyncClient() as client:
        hop = await probe_edge(client, "example.com", timeout=2.0)

    assert hop.edge_colo == "FRA"
    assert hop.source == "cf_ray"


@pytest.mark.asyncio
async def test_probe_edge_swallows_connection_error(httpx_mock: HTTPXMock):
    httpx_mock.add_exception(httpx.ConnectError("boom"))

    async with httpx.AsyncClient() as client:
        hop = await probe_edge(client, "example.com", timeout=2.0)

    assert hop == AnycastHop(target="example.com", source="none")
