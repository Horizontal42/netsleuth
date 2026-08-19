from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from netsleuth.models import PingResult
from netsleuth.probes.latency import summarize_ping, tcp_connect_rtt, _resolve, _icmp_samples


def test_summarize_ping_calculates_correct_stats():
    # Provide enough samples to calculate both rtt_stats and jitter_matrix
    samples = [10.0, 12.0, 14.0, 16.0]
    result = summarize_ping("label1", "host.com", "1.1.1.1", "tcp", samples)

    assert isinstance(result, PingResult)
    assert result.label == "label1"
    assert result.host == "host.com"
    assert result.resolved_ip == "1.1.1.1"
    assert result.method == "tcp"
    assert result.sent == 4
    assert result.received == 4
    assert result.loss_pct == 0.0
    assert result.min_ms == 10.0
    assert result.max_ms == 16.0
    assert result.avg_ms == 13.0
    assert result.mdev_ms == pytest.approx(2.0)
    assert result.jitter_ms == pytest.approx(2.0)
    assert result.p95_ms == pytest.approx(15.7)
    assert result.cv is not None
    assert result.samples == samples


@pytest.mark.asyncio
@patch("asyncio.open_connection", new_callable=AsyncMock)
@patch("time.perf_counter")
async def test_tcp_connect_rtt_success(mock_perf, mock_open_conn):
    # time.perf_counter called at began and before returning
    mock_perf.side_effect = [1.0, 1.05]

    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_open_conn.return_value = (mock_reader, mock_writer)

    rtt = await tcp_connect_rtt("host.com", 443, 2.0)

    # 0.05 seconds = 50.0 ms
    assert rtt == pytest.approx(50.0)
    mock_open_conn.assert_called_once_with("host.com", 443, local_addr=None)
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()


@pytest.mark.asyncio
@patch("asyncio.open_connection", new_callable=AsyncMock)
async def test_tcp_connect_rtt_timeout(mock_open_conn):
    mock_open_conn.side_effect = asyncio.TimeoutError
    rtt = await tcp_connect_rtt("host.com")
    assert rtt is None


@pytest.mark.asyncio
@patch("asyncio.open_connection", new_callable=AsyncMock)
async def test_tcp_connect_rtt_oserror(mock_open_conn):
    mock_open_conn.side_effect = OSError
    rtt = await tcp_connect_rtt("host.com")
    assert rtt is None

@pytest.mark.asyncio
async def test_resolve_success():
    # Mock loop.getaddrinfo via asyncio.get_running_loop
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", new_callable=AsyncMock) as mock_getaddrinfo:
        # getaddrinfo returns list of tuples: (family, type, proto, canonname, sockaddr)
        # sockaddr is (address, port) for IPv4
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('1.2.3.4', 0))
        ]
        ip = await _resolve("host.com")
        assert ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_resolve_failure():
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", new_callable=AsyncMock) as mock_getaddrinfo:
        mock_getaddrinfo.side_effect = OSError
        ip = await _resolve("host.com")
        assert ip is None


@pytest.mark.asyncio
@patch("netsleuth.probes.latency.asyncio.to_thread", new_callable=AsyncMock)
async def test_icmp_samples_win(mock_to_thread):
    mock_to_thread.return_value = [10.0, 15.0]
    samples = await _icmp_samples("host.com", 2, 0.5, 2.0, "icmp_win", source_ip=None)
    assert samples == [10.0, 15.0]
    mock_to_thread.assert_called_once()
    # The first argument should be the ping_samples_win function
    func_arg = mock_to_thread.call_args[0][0]
    assert func_arg.__name__ == "ping_samples_win"
    # The remaining arguments
    assert mock_to_thread.call_args[0][1:] == ("host.com", 2, 0.5, 2.0, None)


@pytest.mark.asyncio
async def test_icmp_samples_unix_raw():
    mock_result = MagicMock()
    mock_result.rtts = [10.0, 12.0]
    mock_async_ping = AsyncMock(return_value=mock_result)

    with patch.dict("sys.modules", {"icmplib": MagicMock(async_ping=mock_async_ping)}):
        samples = await _icmp_samples("host.com", 2, 0.5, 2.0, "icmp_raw")

        assert samples == [10.0, 12.0]
        mock_async_ping.assert_called_once_with(
            "host.com", count=2, interval=0.5, timeout=2.0, privileged=True, source=None
        )


@pytest.mark.asyncio
async def test_icmp_samples_unix_dgram_padded():
    mock_result = MagicMock()
    # Return fewer samples than count (simulating packet loss)
    mock_result.rtts = [10.0]
    mock_async_ping = AsyncMock(return_value=mock_result)

    with patch.dict("sys.modules", {"icmplib": MagicMock(async_ping=mock_async_ping)}):
        samples = await _icmp_samples("host.com", 3, 0.5, 2.0, "icmp_dgram")

        # Should be padded with Nones to length 3
        assert samples == [10.0, None, None]
        mock_async_ping.assert_called_once_with(
            "host.com", count=3, interval=0.5, timeout=2.0, privileged=False, source=None
        )


from netsleuth.probes.latency import ping_host, ping_fanout


@pytest.mark.asyncio
@patch("netsleuth.probes.latency._resolve", new_callable=AsyncMock)
@patch("netsleuth.probes.latency._icmp_samples", new_callable=AsyncMock)
async def test_ping_host_icmp_success(mock_icmp_samples, mock_resolve):
    mock_resolve.return_value = "1.2.3.4"
    mock_icmp_samples.return_value = [10.0, 12.0]

    result = await ping_host("host.com", "label1", 2, 0.5, 2.0, "icmp_raw")

    assert isinstance(result, PingResult)
    assert result.method == "icmp_raw"
    assert result.resolved_ip == "1.2.3.4"
    assert result.samples == [10.0, 12.0]
    mock_icmp_samples.assert_called_once_with("host.com", 2, 0.5, 2.0, "icmp_raw", None)


@pytest.mark.asyncio
@patch("netsleuth.probes.latency._resolve", new_callable=AsyncMock)
@patch("netsleuth.probes.latency._icmp_samples", new_callable=AsyncMock)
@patch("netsleuth.probes.latency.tcp_connect_rtt", new_callable=AsyncMock)
async def test_ping_host_icmp_exception_fallback(mock_tcp_connect, mock_icmp_samples, mock_resolve):
    mock_resolve.return_value = "1.2.3.4"
    mock_icmp_samples.side_effect = Exception("ICMP failed")
    mock_tcp_connect.side_effect = [15.0, 16.0]

    result = await ping_host("host.com", "label1", 2, 0.0, 2.0, "icmp_raw")

    assert result.method == "tcp"
    assert result.samples == [15.0, 16.0]
    assert mock_tcp_connect.call_count == 2


@pytest.mark.asyncio
@patch("netsleuth.probes.latency._resolve", new_callable=AsyncMock)
@patch("netsleuth.probes.latency.tcp_connect_rtt", new_callable=AsyncMock)
async def test_ping_host_tcp_direct(mock_tcp_connect, mock_resolve):
    mock_resolve.return_value = "1.2.3.4"
    mock_tcp_connect.side_effect = [20.0, 21.0]

    result = await ping_host("host.com", "label1", 2, 0.0, 2.0, "tcp")

    assert result.method == "tcp"
    assert result.samples == [20.0, 21.0]
    assert mock_tcp_connect.call_count == 2


@pytest.mark.asyncio
async def test_ping_host_semaphore():
    semaphore = asyncio.Semaphore(1)

    with patch("netsleuth.probes.latency.ping_host", new_callable=AsyncMock) as mock_ping_host:
        mock_ping_host.return_value = MagicMock()

        # When called with a semaphore, ping_host calls itself without the semaphore inside the block
        await ping_host("host.com", "label1", 2, 0.5, 2.0, "tcp", semaphore=semaphore)

        mock_ping_host.assert_called_once_with(
            "host.com", "label1", 2, 0.5, 2.0, "tcp", None
        )


@pytest.mark.asyncio
@patch("netsleuth.probes.latency.choose_latency_backend")
@patch("netsleuth.probes.latency.ping_host", new_callable=AsyncMock)
async def test_ping_fanout(mock_ping_host, mock_choose_backend):
    mock_choose_backend.return_value = "icmp_dgram"

    res1 = PingResult(label="label1", host="host1.com", method="icmp_dgram")
    res2 = PingResult(label="label2", host="host2.com", method="icmp_dgram")

    # We gather so order might be tricky, mock needs to handle multiple calls
    def ping_host_side_effect(host, label, *args, **kwargs):
        if host == "host1.com":
            return res1
        return res2

    mock_ping_host.side_effect = ping_host_side_effect

    hosts = [("label1", "host1.com"), ("label2", "host2.com")]
    caps = MagicMock()

    results = await ping_fanout(hosts, caps, 2, 0.5, 2.0)

    assert len(results) == 2
    assert res1 in results
    assert res2 in results
    mock_choose_backend.assert_called_once_with(caps)
    assert mock_ping_host.call_count == 2
