from __future__ import annotations

import unittest.mock

import dns.exception
import pytest

from netsleuth.probes.nat64 import detect_nat64


@pytest.fixture
def mock_resolver(monkeypatch):
    mock_resolve = unittest.mock.AsyncMock()
    # We patch the Resolver class's resolve method
    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", mock_resolve)
    return mock_resolve


@pytest.mark.asyncio
async def test_detect_nat64_returns_prefix_on_success(mock_resolver):
    # Mock Answer objects with string representation that match nat64_prefix_from_aaaa logic.
    # The AAAA should encode one of the _IPV4ONLY_ARPA_A (192.0.0.170, 192.0.0.171).
    # 64:ff9b::c000:aa is the well-known prefix for 192.0.0.170
    class MockAnswer:
        def __str__(self):
            return "64:ff9b::c000:aa"

    mock_resolver.return_value = [MockAnswer()]

    result = await detect_nat64(timeout=1.0)
    assert result == "64:ff9b::/96"


@pytest.mark.asyncio
async def test_detect_nat64_returns_none_if_no_synthesized_answer(mock_resolver):
    class MockAnswer:
        def __str__(self):
            return "2606:4700:4700::1111"

    mock_resolver.return_value = [MockAnswer()]

    result = await detect_nat64(timeout=1.0)
    assert result is None


@pytest.mark.asyncio
async def test_detect_nat64_returns_none_on_dns_exception(mock_resolver):
    mock_resolver.side_effect = dns.exception.Timeout

    result = await detect_nat64(timeout=1.0)
    assert result is None
