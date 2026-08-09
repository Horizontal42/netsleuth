from __future__ import annotations

import time
from unittest.mock import patch

from netsleuth.probes.icmp_win import IP_REQ_TIMED_OUT, IcmpReply, trace_hops_win


def _fake_gethostbyname(host: str) -> str:
    return "203.0.113.1"


def test_trace_hops_win_total_elapsed_is_bounded_by_the_total_budget_not_hops_times_timeout():
    # Every hop times out; each fake call sleeps for its per-hop timeout to
    # simulate a genuinely unresponsive router. Old (buggy) code handed the
    # *entire* 100ms total budget to every one of the 30 hops as its own
    # per-hop timeout, i.e. ~3s worst case for this scenario. The fix must
    # divide that budget across hops instead, keeping total wall time close
    # to the 100ms total budget.
    call_timeouts: list[int] = []

    def fake_echo_once(dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netsleuth", source_ip=None) -> IcmpReply:
        call_timeouts.append(timeout_ms)
        time.sleep(timeout_ms / 1000.0)
        return IcmpReply(address=None, status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)

    with (
        patch("netsleuth.probes.icmp_win.socket.gethostbyname", side_effect=_fake_gethostbyname),
        patch("netsleuth.probes.icmp_win.echo_once", side_effect=fake_echo_once),
    ):
        started = time.monotonic()
        trace_hops_win("example.invalid", max_hops=30, timeout_ms=100)
        elapsed = time.monotonic() - started

    # Comfortably under the ~3s the old per-hop-gets-the-whole-budget bug would
    # have produced here, while still generous about scheduling jitter.
    assert elapsed < 1.0
    # Every individual hop got a fraction of the total budget, not the whole thing.
    assert call_timeouts
    assert all(t == 100 // 30 for t in call_timeouts)


def test_trace_hops_win_per_hop_timeout_is_capped_even_for_a_huge_total_budget():
    call_timeouts: list[int] = []

    def fake_echo_once(dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netsleuth", source_ip=None) -> IcmpReply:
        call_timeouts.append(timeout_ms)
        return IcmpReply(address=None, status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)

    with (
        patch("netsleuth.probes.icmp_win.socket.gethostbyname", side_effect=_fake_gethostbyname),
        patch("netsleuth.probes.icmp_win.echo_once", side_effect=fake_echo_once),
    ):
        # A single-hop trace with a huge total budget (e.g. subprocess_seconds=60s
        # divided across a small max_hops) must still not hand the whole budget
        # to one hop - it's capped at _MAX_HOP_TIMEOUT_MS (4s).
        trace_hops_win("example.invalid", max_hops=1, timeout_ms=60_000)

    assert call_timeouts == [4000]


def test_trace_hops_win_happy_path_hop_count_and_ok_break_are_unchanged():
    from netsleuth.probes.icmp_win import IP_SUCCESS

    def fake_echo_once(dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netsleuth", source_ip=None) -> IcmpReply:
        if ttl < 3:
            return IcmpReply(address=f"10.0.0.{ttl}", status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)
        return IcmpReply(address="203.0.113.1", status=IP_SUCCESS, rtt_ms=5.0, ttl=64)

    with (
        patch("netsleuth.probes.icmp_win.socket.gethostbyname", side_effect=_fake_gethostbyname),
        patch("netsleuth.probes.icmp_win.echo_once", side_effect=fake_echo_once),
    ):
        hops = trace_hops_win("example.invalid", max_hops=30, timeout_ms=60_000)

    # Fast-responding hops still stop the loop at the first success, same as before.
    assert [ttl for ttl, _ in hops] == [1, 2, 3]
    assert hops[-1][1].status == IP_SUCCESS
