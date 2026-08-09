from __future__ import annotations

from typing import NamedTuple


class RttStats(NamedTuple):
    sent: int
    received: int
    loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    mdev_ms: float | None
    jitter_ms: float | None


def rtt_stats(samples: list[float | None]) -> RttStats:
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
