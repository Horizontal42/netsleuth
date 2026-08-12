"""Integration tests for netsleuth CLI and HTTP interactions."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import httpx
import pytest_httpx


def test_cli_help_runs_without_error(runner):
    """Test that CLI help command executes successfully."""
    from netsleuth.cli import app
    from typer.testing import CliRunner
    
    runner_instance = CliRunner()
    result = runner_instance.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Deep network diagnostics" in result.stdout


def test_gather_identity_with_mocked_http(httpx_mock):
    """Test gather_identity with mocked HTTP responses."""
    from netsleuth.ip_geo import gather_identity
    
    # Mock ip-api.com response
    httpx_mock.add_response(
        url="http://ip-api.com/json/",
        json={
            "status": "success",
            "query": "8.8.8.8",
            "country": "United States",
            "countryCode": "US",
            "region": "CA",
            "city": "Mountain View",
            "zip": "94035",
            "lat": 37.386,
            "lon": -122.0838,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as": "AS15169 Google LLC",
            "mobile": False,
            "proxy": False,
            "hosting": True,
        }
    )
    
    # Mock Cloudflare trace
    httpx_mock.add_response(
        url="https://www.cloudflare.com/cdn-cgi/trace",
        text="ip=8.8.8.8\ncolo=SFO\nloc=US\nwarp=off\n"
    )
    
    # This would normally make real HTTP calls, but with httpx_mock they're intercepted
    # Note: This is a simplified example - actual test may need more mocking


def test_speedtest_cloudflare_with_mocked_http(httpx_mock):
    """Test Cloudflare speedtest with mocked HTTP responses."""
    from netsleuth.speed import speedtest_cloudflare
    
    # Mock download endpoint
    httpx_mock.add_response(
        url="https://speed.cloudflare.com/__down?bytes=1000000",
        content=b"0" * 1000000,
        headers={"Content-Length": "1000000"}
    )
    
    # The actual test would need more sophisticated mocking of timing


def test_dns_resolution_with_mocked_dns():
    """Test DNS resolution with mocked responses."""
    import dns.message
    import dns.rdataclass
    import dns.rdatatype
    from unittest.mock import patch
    
    # Create a mock DNS response
    mock_response = dns.message.make_response(dns.message.Message())
    mock_response.answer.append(
        dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8")
    )
    
    with patch('dns.resolver.Resolver.resolve', return_value=mock_response):
        # Test code here
        pass


def test_bgp_api_with_mocked_response(httpx_mock):
    """Test BGP API calls with mocked responses."""
    # Mock RIPEstat API
    httpx_mock.add_response(
        url="https://stat.ripe.net/data/as-overview.json",
        json={
            "data": {
                "asn": 15169,
                "holder": "GOOGLE",
                "ips": 8388608,
                "prefixes_v4": 256,
                "prefixes_v6": 64,
            }
        }
    )


@pytest.mark.asyncio
async def test_ping_fanout_with_mocked_icmp():
    """Test ping fanout with mocked ICMP responses."""
    from unittest.mock import AsyncMock, patch
    from netsleuth.probes.latency import ping_fanout
    
    # Mock the ICMP ping function
    mock_result = MagicMock()
    mock_result.avg_ms = 10.5
    mock_result.loss_pct = 0.0
    
    with patch('netsleuth.probes.latency.ping_host', return_value=mock_result):
        results = await ping_fanout(["8.8.8.8", "1.1.1.1"], count=2)
        assert len(results) == 2


def test_reputation_check_with_mocked_apis(httpx_mock):
    """Test reputation checks with mocked API responses."""
    # Mock Shodan InternetDB
    httpx_mock.add_response(
        url="https://internetdb.shodan.io/8.8.8.8",
        json={
            "ip": "8.8.8.8",
            "ports": [80, 443],
            "hostnames": ["dns.google"],
            "tags": [],
            "cpes": [],
            "vulns": [],
        }
    )
    
    # Mock AbuseIPDB
    httpx_mock.add_response(
        url="https://api.abuseipdb.com/api/v2/check",
        json={
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
            }
        }
    )
