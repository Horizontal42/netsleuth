from __future__ import annotations

from typing import NamedTuple


class RttStats(NamedTuple):
    """Statistics computed from RTT samples.

    Attributes:
        sent: Number of probes sent.
        received: Number of probes received.
        loss_pct: Percentage of lost probes (0-100).
        min_ms: Minimum RTT in milliseconds, or None if no samples.
        avg_ms: Average RTT in milliseconds, or None if no samples.
        max_ms: Maximum RTT in milliseconds, or None if no samples.
        mdev_ms: Mean deviation of RTT in milliseconds, or None if no samples.
        jitter_ms: Jitter (average inter-packet delay variation) in milliseconds, or None.
    """
    sent: int
    received: int
    loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    mdev_ms: float | None
    jitter_ms: float | None


def rtt_stats(samples: list[float | None]) -> RttStats:
    """Compute RTT statistics from a list of samples.

    Args:
        samples: A list of RTT measurements in milliseconds, where None represents
            a lost/timeout probe.

    Returns:
        A RttStats named tuple containing sent/received counts, loss percentage,
        min/avg/max RTT, mean deviation, and jitter. All timing fields are None
        if no samples were received.

    Note:
        Jitter is computed as the average absolute difference between consecutive
        non-None samples. If fewer than two valid samples exist, jitter is 0.0.
    """
    sent = len(samples)
    got = [s for s in samples if s is not None]
    received = len(got)
    loss_pct = 0.0 if sent == 0 else round(100.0 * (sent - received) / sent, 3)
    if not got:
        return RttStats(sent, 0, loss_pct, None, None, None, None, None)
    avg = sum(got) / received
    mdev = sum(abs(v - avg) for v in got) / received
    deltas = [
        abs(b - a)
        for a, b in zip(samples, samples[1:])
        if a is not None and b is not None
    ]
    jitter = sum(deltas) / len(deltas) if deltas else 0.0
    return RttStats(
        sent=sent,
        received=received,
        loss_pct=loss_pct,
        min_ms=round(min(got), 3),
        avg_ms=round(avg, 3),
        max_ms=round(max(got), 3),
        mdev_ms=round(mdev, 3),
        jitter_ms=round(jitter, 3),
    )


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (p / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


class JitterMatrix(NamedTuple):
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    stdev_ms: float | None
    cv: float | None
    outlier_pct: float


def jitter_matrix(samples: list[float | None]) -> JitterMatrix:
    got = [s for s in samples if s is not None]
    if not got:
        return JitterMatrix(None, None, None, None, None, 0.0)
    p50 = round(percentile(got, 50.0), 3)
    p95 = round(percentile(got, 95.0), 3)
    p99 = round(percentile(got, 99.0), 3)
    if len(got) == 1:
        return JitterMatrix(p50, p95, p99, 0.0, 0.0, 0.0)
    mean = sum(got) / len(got)
    stdev = (sum((v - mean) ** 2 for v in got) / len(got)) ** 0.5
    cv = 0.0 if mean == 0 else stdev / mean
    outliers = sum(1 for v in got if v > p95)
    outlier_pct = round(100.0 * outliers / len(got), 3)
    return JitterMatrix(p50, p95, p99, round(stdev, 3), round(cv, 3), outlier_pct)
