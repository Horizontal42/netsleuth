from __future__ import annotations

import pytest

from netsleuth.probes.latency import summarize_ping


def test_summarize_builds_a_complete_ping_result():
    result = summarize_ping(
        label="cloudflare-dns",
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_dgram",
        samples=[10.0, 12.0, 14.0, 16.0],
    )
    assert result.label == "cloudflare-dns"
    assert result.host == "1.1.1.1"
    assert result.resolved_ip == "1.1.1.1"
    assert result.method == "icmp_dgram"
    assert result.sent == 4
    assert result.received == 4
    assert result.loss_pct == 0.0
    assert result.min_ms == 10.0
    assert result.avg_ms == 13.0
    assert result.max_ms == 16.0
    assert result.mdev_ms == pytest.approx(2.0)
    assert result.jitter_ms == pytest.approx(2.0)
    assert result.samples == [10.0, 12.0, 14.0, 16.0]


def test_summarize_keeps_timeout_positions_in_the_sample_list():
    result = summarize_ping("h", "example.test", None, "tcp", [None, 20.0, None, 24.0])
    assert result.samples == [None, 20.0, None, 24.0]
    assert result.sent == 4
    assert result.received == 2
    assert result.loss_pct == 50.0


def test_summarize_of_an_all_timeout_run_is_not_an_error():
    result = summarize_ping("h", "example.test", None, "icmp_win", [None, None, None])
    assert result.received == 0
    assert result.loss_pct == 100.0
    assert result.avg_ms is None
    assert result.jitter_ms is None


def test_summarize_of_a_single_sample_reports_zero_jitter():
    result = summarize_ping("h", "1.1.1.1", "1.1.1.1", "cfL4", [9.0])
    assert result.min_ms == result.avg_ms == result.max_ms == 9.0
    assert result.jitter_ms == 0.0
    assert result.mdev_ms == 0.0


def test_summarize_of_zero_probes_is_a_well_formed_empty_result():
    result = summarize_ping("h", "1.1.1.1", None, "none", [])
    assert result.sent == 0
    assert result.received == 0
    assert result.loss_pct == 0.0
    assert result.samples == []


def test_the_method_tag_is_preserved_verbatim():
    for method in ("icmp_win", "icmp_dgram", "icmp_raw", "tcp", "cfL4"):
        assert summarize_ping("h", "x", None, method, [1.0]).method == method
