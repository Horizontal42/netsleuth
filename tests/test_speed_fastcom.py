import httpx
import pytest

from netsleuth.config import Speedtest
from netsleuth.speed import tier_fastcom


async def test_tier_fastcom_happy_path(httpx_mock):
    config = Speedtest()
    api_url = config.fastcom_api_url

    httpx_mock.add_response(
        url=f"{api_url}?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3",
        json={
            "targets": [
                {"url": "https://server1.example.com/speedtest", "location": {"country": "US"}},
                {"url": "https://server2.example.com/speedtest", "location": {"country": "US"}},
            ]
        },
    )

    httpx_mock.add_response(
        url="https://server1.example.com/speedtest",
        content=b"A" * 125000, # 1 Mbit
    )

    httpx_mock.add_response(
        url="https://server2.example.com/speedtest",
        content=b"B" * 250000, # 2 Mbit
    )

    async with httpx.AsyncClient() as client:
        result = await tier_fastcom(client, config, timeout=5.0)

    assert result.method == "fastcom"
    assert result.download_mbps is not None
    assert result.download_mbps > 0
    assert result.upload_mbps is None
    assert result.server == "server1.example.com"
    assert result.netflix_oca_onnet is True
    assert result.server_country == "US"


async def test_tier_fastcom_no_targets(httpx_mock):
    config = Speedtest()
    api_url = config.fastcom_api_url

    httpx_mock.add_response(
        url=f"{api_url}?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3",
        json={"targets": []},
    )

    async with httpx.AsyncClient() as client:
        result = await tier_fastcom(client, config, timeout=5.0)

    assert result.method == "fastcom"
    assert result.download_mbps == 0.0
    assert result.server is None
    assert result.netflix_oca_onnet is None


async def test_tier_fastcom_missing_urls(httpx_mock):
    config = Speedtest()
    api_url = config.fastcom_api_url

    httpx_mock.add_response(
        url=f"{api_url}?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3",
        json={
            "targets": [
                {"location": {"country": "US"}}, # missing URL
                {"url": "https://server1.example.com/speedtest", "location": {"country": "US"}},
            ]
        },
    )

    httpx_mock.add_response(
        url="https://server1.example.com/speedtest",
        content=b"A" * 125000, # 1 Mbit
    )

    async with httpx.AsyncClient() as client:
        result = await tier_fastcom(client, config, timeout=5.0)

    assert result.method == "fastcom"
    assert result.download_mbps is not None
    assert result.download_mbps > 0
    assert result.server is None
    assert result.netflix_oca_onnet is True


async def test_tier_fastcom_api_error(httpx_mock):
    config = Speedtest()
    api_url = config.fastcom_api_url

    httpx_mock.add_response(
        url=f"{api_url}?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3",
        status_code=500,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError) as exc:
            await tier_fastcom(client, config, timeout=5.0)

    assert exc.value.response.status_code == 500


async def test_tier_fastcom_download_error(httpx_mock):
    config = Speedtest()
    api_url = config.fastcom_api_url

    httpx_mock.add_response(
        url=f"{api_url}?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3",
        json={
            "targets": [
                {"url": "https://server1.example.com/speedtest", "location": {"country": "US"}},
            ]
        },
    )

    httpx_mock.add_response(
        url="https://server1.example.com/speedtest",
        status_code=404,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError) as exc:
            await tier_fastcom(client, config, timeout=5.0)

    assert exc.value.response.status_code == 404
