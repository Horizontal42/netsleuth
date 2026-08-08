from __future__ import annotations

import math

import pytest

from netcheck.stats import percentile, rtt_stats


def test_all_samples_present():
    s = rtt_stats([10.0, 12.0, 14.0, 16.0])
    assert s.sent == 4
    assert s.received == 4
    assert s.loss_pct == 0.0
    assert s.min_ms == 10.0
    assert s.max_ms == 16.0
    assert s.avg_ms == 13.0
    assert s.mdev_ms == pytest.approx(2.0)
    assert s.jitter_ms == pytest.approx(2.0)


def test_loss_is_the_share_of_missing_samples():
    s = rtt_stats([10.0, None, None, 20.0])
    assert s.sent == 4
    assert s.received == 2
    assert s.loss_pct == 50.0
    assert s.avg_ms == 15.0


def test_jitter_ignores_gaps_and_uses_consecutive_received_pairs():
    # Consecutive received pairs are (10,20) and (20,26): mean |diff| = (10+6)/2 = 8.
    s = rtt_stats([10.0, 20.0, None, 20.0, 26.0])
    assert s.jitter_ms == pytest.approx(8.0)


def test_all_timeouts_yield_full_loss_and_no_timing_values():
    s = rtt_stats([None, None, None])
    assert s.sent == 3
    assert s.received == 0
    assert s.loss_pct == 100.0
    assert s.min_ms is None
    assert s.avg_ms is None
    assert s.max_ms is None
    assert s.mdev_ms is None
    assert s.jitter_ms is None


def test_single_sample_has_zero_deviation_and_zero_jitter():
    s = rtt_stats([13.5])
    assert s.received == 1
    assert s.min_ms == s.avg_ms == s.max_ms == 13.5
    assert s.mdev_ms == 0.0
    assert s.jitter_ms == 0.0


def test_empty_input_is_not_a_division_by_zero():
    s = rtt_stats([])
    assert s.sent == 0
    assert s.received == 0
    assert s.loss_pct == 0.0
    assert s.avg_ms is None


def test_every_stat_is_finite_so_json_serialization_cannot_break():
    for samples in ([], [None], [1.0], [1.0, None, 3.0]):
        for value in rtt_stats(samples):
            assert value is None or math.isfinite(value)


def test_percentile_interpolates_between_ranks():
    values = [1.0, 2.0, 3.0, 4.0]
    assert percentile(values, 0.0) == 1.0
    assert percentile(values, 100.0) == 4.0
    assert percentile(values, 50.0) == pytest.approx(2.5)
    assert percentile(values, 90.0) == pytest.approx(3.7)


def test_percentile_handles_single_and_empty_inputs():
    assert percentile([7.0], 90.0) == 7.0
    assert percentile([], 90.0) == 0.0
