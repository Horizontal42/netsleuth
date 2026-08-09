from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from netsleuth.speed import bufferbloat_delta, mbps, ookla_interface_args, parse_server_timing_cfl4, throughput_from_samples


def test_mbps_converts_bytes_and_seconds():
    assert mbps(1_000_000, 1.0) == pytest.approx(8.0)
    assert mbps(12_500_000, 1.0) == pytest.approx(100.0)
    assert mbps(25_000_000, 2.0) == pytest.approx(100.0)


def test_mbps_of_a_zero_or_negative_interval_is_zero_not_infinity():
    # Zero-duration timing math is exactly where inf leaks into the JSON report.
    assert mbps(1_000_000, 0.0) == 0.0
    assert mbps(1_000_000, -1.0) == 0.0


def test_mbps_of_no_bytes_is_zero():
    assert mbps(0, 1.5) == 0.0


def test_throughput_uses_the_ninetieth_percentile_of_the_samples():
    samples = [(1_000_000, 1.0), (1_000_000, 0.5), (1_000_000, 0.4), (1_000_000, 0.25)]
    # Per-sample Mbps: 8, 16, 20, 32 -> p90 interpolates to 28.4
    assert throughput_from_samples(samples) == pytest.approx(28.4)


def test_throughput_of_a_single_sample_is_that_sample():
    assert throughput_from_samples([(12_500_000, 1.0)]) == pytest.approx(100.0)


def test_throughput_of_no_samples_is_zero():
    assert throughput_from_samples([]) == 0.0


def test_cfl4_header_is_parsed_into_typed_stats():
    header = (
        'cfL4;desc="?proto=tcp&rtt=12345&min_rtt=11000&rtt_var=1500&sent=100&recv=200'
        '&lost=0&retrans=0&sent_bytes=1000&recv_bytes=1048576&delivery_rate=35000000'
        '&cwnd=42&unsent_bytes=0&cid=abcdef&ts=1&x=0"'
    )
    stats = parse_server_timing_cfl4(header)
    assert stats is not None
    assert stats.rtt_ms == pytest.approx(12.345)
    assert stats.min_rtt_ms == pytest.approx(11.0)
    assert stats.rtt_var_ms == pytest.approx(1.5)
    assert stats.delivery_rate_bps == 35000000
    assert stats.cwnd == 42
    assert stats.unsent_bytes == 0
    assert stats.recv_bytes == 1048576


def test_cfl4_parsing_picks_its_entry_out_of_a_multi_metric_header():
    header = 'cfRequestDuration;dur=42.1, cfL4;desc="?proto=tcp&rtt=9000&cwnd=10", cfCacheStatus;desc="HIT"'
    stats = parse_server_timing_cfl4(header)
    assert stats is not None
    assert stats.rtt_ms == pytest.approx(9.0)
    assert stats.cwnd == 10
    assert stats.delivery_rate_bps is None


def test_cfl4_parsing_of_a_header_without_the_entry_is_none():
    assert parse_server_timing_cfl4("cfCacheStatus;desc=HIT") is None
    assert parse_server_timing_cfl4("") is None


def test_cfl4_parsing_survives_unexpected_values():
    stats = parse_server_timing_cfl4('cfL4;desc="?proto=tcp&rtt=notanumber&cwnd=7"')
    assert stats is not None
    assert stats.rtt_ms is None
    assert stats.cwnd == 7


def test_bufferbloat_delta_is_the_rise_over_the_idle_baseline():
    assert bufferbloat_delta(12.0, [15.0, 60.0, 200.0, 210.0]) == pytest.approx(196.5)


def test_bufferbloat_delta_never_goes_negative():
    assert bufferbloat_delta(50.0, [10.0, 12.0, 11.0]) == 0.0


def test_ookla_interface_args_prefers_interface_name_over_ip():
    assert ookla_interface_args(iface_name="Ethernet", ipv4="192.168.3.72") == ["--interface", "Ethernet"]


def test_ookla_interface_args_falls_back_to_ip_without_a_name():
    assert ookla_interface_args(iface_name=None, ipv4="192.168.3.72") == ["--ip", "192.168.3.72"]


def test_ookla_interface_args_is_empty_without_a_forced_bind():
    assert ookla_interface_args(iface_name=None, ipv4=None) == []


def test_bufferbloat_delta_needs_both_a_baseline_and_samples():
    assert bufferbloat_delta(None, [10.0]) is None
    assert bufferbloat_delta(12.0, []) is None


from netsleuth.models import SpeedResult
from netsleuth.speed import NDT7_CONSENT_NOTICE, run_speed_cascade


async def test_cascade_stops_at_the_first_tier_that_returns_a_download_figure():
    calls: list[str] = []

    async def ookla() -> SpeedResult:
        calls.append("ookla")
        return SpeedResult(method="ookla_bin", download_mbps=312.4, upload_mbps=41.0)

    async def cloudflare() -> SpeedResult:
        calls.append("cloudflare")
        return SpeedResult(method="cloudflare", download_mbps=280.0)

    result = await run_speed_cascade([("ookla_bin", ookla), ("cloudflare", cloudflare)])
    assert result.method == "ookla_bin"
    assert result.download_mbps == 312.4
    assert calls == ["ookla"]
    assert [a.tier for a in result.tier_attempts] == ["ookla_bin"]
    assert result.tier_attempts[0].ok is True


async def test_cascade_records_a_failed_tier_and_moves_on():
    async def ookla() -> SpeedResult:
        raise FileNotFoundError("speedtest binary not on PATH")

    async def cloudflare() -> SpeedResult:
        return SpeedResult(method="cloudflare", download_mbps=280.0)

    result = await run_speed_cascade([("ookla_bin", ookla), ("cloudflare", cloudflare)])
    assert result.method == "cloudflare"
    assert [a.tier for a in result.tier_attempts] == ["ookla_bin", "cloudflare"]
    assert result.tier_attempts[0].ok is False
    assert "not on PATH" in result.tier_attempts[0].reason
    assert result.tier_attempts[1].ok is True


async def test_a_tier_that_returns_zero_download_counts_as_a_failure():
    async def dead() -> SpeedResult:
        return SpeedResult(method="cloudflare", download_mbps=0.0)

    async def alive() -> SpeedResult:
        return SpeedResult(method="fastcom", download_mbps=95.0)

    result = await run_speed_cascade([("cloudflare", dead), ("fastcom", alive)])
    assert result.method == "fastcom"
    assert result.tier_attempts[0].ok is False
    assert result.tier_attempts[0].reason == "no throughput measured"


async def test_cascade_exhaustion_is_a_failed_result_not_an_exception():
    async def boom() -> SpeedResult:
        raise OSError("network unreachable")

    result = await run_speed_cascade([("ookla_bin", boom), ("cloudflare", boom), ("fastcom", boom)])
    assert isinstance(result, SpeedResult)
    assert result.method == "none"
    assert result.download_mbps is None
    assert [a.tier for a in result.tier_attempts] == ["ookla_bin", "cloudflare", "fastcom"]
    assert all(a.ok is False for a in result.tier_attempts)


async def test_an_empty_cascade_is_a_failed_result():
    result = await run_speed_cascade([])
    assert result.method == "none"
    assert result.tier_attempts == []


async def test_cascade_records_exception_class_name_when_no_message_provided():
    async def bad() -> SpeedResult:
        raise Exception()

    result = await run_speed_cascade([("bad", bad)])
    assert result.method == "none"
    assert len(result.tier_attempts) == 1
    assert result.tier_attempts[0].ok is False
    assert result.tier_attempts[0].reason == "Exception"


async def test_cascade_never_swallows_cancellation():
    import asyncio

    async def cancelled() -> SpeedResult:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_speed_cascade([("ookla_bin", cancelled)])


def test_the_ndt7_consent_notice_states_what_gets_published():
    assert "CC0" in NDT7_CONSENT_NOTICE
    assert "IP" in NDT7_CONSENT_NOTICE
    assert "public" in NDT7_CONSENT_NOTICE.lower()


from netsleuth.speed import tier_ookla


async def test_tier_ookla_success_parses_json():
    mock_proc = AsyncMock()
    mock_payload = {
        "download": {"bytes": 12500000, "elapsed": 1000}, # 100 Mbps
        "upload": {"bytes": 1250000, "elapsed": 1000}, # 10 Mbps
        "server": {"name": "TestServer", "location": "TestCity"},
        "ping": {"latency": 15.5}
    }
    mock_proc.communicate.return_value = (json.dumps(mock_payload).encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        result = await tier_ookla("speedtest", None, 10.0)

        mock_exec.assert_called_once_with(
            "speedtest", "--format=json", "--accept-license", "--accept-gdpr",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        assert result.method == "ookla_bin"
        assert result.download_mbps == 100.0
        assert result.upload_mbps == 10.0
        assert result.server == "TestServer (TestCity)"
        assert result.idle_rtt_ms == 15.5

async def test_tier_ookla_server_args():
    mock_proc = AsyncMock()
    mock_payload = {}
    mock_proc.communicate.return_value = (json.dumps(mock_payload).encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        # Numeric server maps to --server-id
        await tier_ookla("speedtest", "12345", 10.0)
        mock_exec.assert_called_with(
            "speedtest", "--format=json", "--accept-license", "--accept-gdpr", "--server-id", "12345",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )

        # String server maps to --host
        await tier_ookla("speedtest", "speed.example.com", 10.0)
        mock_exec.assert_called_with(
            "speedtest", "--format=json", "--accept-license", "--accept-gdpr", "--host", "speed.example.com",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )

async def test_tier_ookla_missing_json_fields():
    mock_proc = AsyncMock()
    mock_payload = {} # Empty payload
    mock_proc.communicate.return_value = (json.dumps(mock_payload).encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await tier_ookla("speedtest", None, 10.0)

        assert result.method == "ookla_bin"
        assert result.download_mbps == 0.0
        assert result.upload_mbps == 0.0
        assert result.server == "()"
        assert result.idle_rtt_ms is None


from netsleuth.config import BufferbloatBands
from netsleuth.speed import measure_with_bufferbloat, probe_while


async def test_probe_while_collects_samples_for_the_whole_duration_of_the_work():
    import asyncio

    async def work() -> None:
        await asyncio.sleep(0.25)

    async def probe() -> float | None:
        return 42.0

    samples = await probe_while(work(), probe, interval=0.05)
    assert len(samples) >= 3
    assert all(s == 42.0 for s in samples)


async def test_probe_while_drops_failed_probes_instead_of_recording_none():
    import asyncio

    async def work() -> None:
        await asyncio.sleep(0.15)

    async def probe() -> float | None:
        return None

    assert await probe_while(work(), probe, interval=0.05) == []


async def test_measure_with_bufferbloat_fills_in_both_directions_and_the_grade():
    import asyncio

    loaded = iter([80.0, 90.0, 100.0] * 20)

    async def run_download() -> None:
        await asyncio.sleep(0.15)

    async def run_upload() -> None:
        await asyncio.sleep(0.15)

    async def probe() -> float | None:
        return next(loaded)

    result = await measure_with_bufferbloat(
        SpeedResult(method="cloudflare", download_mbps=300.0, upload_mbps=40.0),
        idle_rtt_ms=12.0,
        bands=BufferbloatBands(),
        run_download=run_download,
        run_upload=run_upload,
        probe=probe,
        interval=0.05,
    )
    assert result.idle_rtt_ms == 12.0
    assert result.loaded_rtt_down_ms is not None
    assert result.loaded_rtt_up_ms is not None
    assert result.bufferbloat_down_ms is not None and result.bufferbloat_down_ms > 60
    assert result.bufferbloat_grade in ("D", "E", "F")


async def test_measure_with_bufferbloat_without_an_idle_baseline_grades_unknown():
    import asyncio

    async def work() -> None:
        await asyncio.sleep(0.05)

    async def probe() -> float | None:
        return 80.0

    result = await measure_with_bufferbloat(
        SpeedResult(method="cloudflare", download_mbps=300.0),
        idle_rtt_ms=None,
        bands=BufferbloatBands(),
        run_download=work,
        run_upload=work,
        probe=probe,
        interval=0.02,
    )
    assert result.bufferbloat_down_ms is None
    assert result.bufferbloat_grade == "?"
