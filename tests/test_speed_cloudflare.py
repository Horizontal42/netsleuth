import pytest
import httpx
from pytest_httpx import HTTPXMock

from netsleuth.config import Speedtest
from netsleuth.speed import tier_cloudflare


@pytest.mark.asyncio
async def test_tier_cloudflare_happy_path(httpx_mock: HTTPXMock):
    cfg = Speedtest(
        download_sizes_bytes=[100, 200],
        upload_sizes_bytes=[50],
        cloudflare_base_url="https://speed.cloudflare.com"
    )

    httpx_mock.add_response(
        url="https://speed.cloudflare.com/__down?bytes=100",
        method="GET",
        content=b"x" * 100,
        headers={"Server-Timing": 'cfL4;desc="?rtt=12345&min_rtt=11000"'}
    )

    httpx_mock.add_response(
        url="https://speed.cloudflare.com/__down?bytes=200",
        method="GET",
        content=b"x" * 200,
        headers={"Server-Timing": 'cfL4;desc="?rtt=12345&min_rtt=11000"'}
    )

    httpx_mock.add_response(
        url="https://speed.cloudflare.com/__up",
        method="POST",
        content=b""
    )

    async with httpx.AsyncClient() as client:
        result = await tier_cloudflare(client, cfg, timeout=2.0)

    assert result.method == "cloudflare"
    assert result.server == "speed.cloudflare.com"

    # We used lengths 100 and 200 for download, so some throughput should be calculated
    assert result.download_mbps is not None
    assert result.download_mbps > 0.0

    # We used length 50 for upload
    assert result.upload_mbps is not None
    assert result.upload_mbps > 0.0

    assert result.cfL4_stats is not None
    assert result.cfL4_stats.rtt_ms == 12.345
    assert result.cfL4_stats.min_rtt_ms == 11.0


@pytest.mark.asyncio
async def test_tier_cloudflare_http_error(httpx_mock: HTTPXMock):
    cfg = Speedtest(
        download_sizes_bytes=[100],
        upload_sizes_bytes=[],
        cloudflare_base_url="https://speed.cloudflare.com"
    )

    httpx_mock.add_response(
        url="https://speed.cloudflare.com/__down?bytes=100",
        method="GET",
        status_code=500
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await tier_cloudflare(client, cfg, timeout=2.0)
