from __future__ import annotations

import asyncio
import threading

import pytest

from netsleuth.models import Capabilities, TraceHop, TraceResult
from netsleuth.probes.icmp_win import (
    IP_REQ_TIMED_OUT,
    IP_SUCCESS,
    IP_TTL_EXPIRED_TRANSIT,
    IcmpReply,
)
from netsleuth.probes.traceroute import (
    _run_in_daemon_thread,
    filter_trace_tiers,
    hops_from_win_replies,
    run_cascade,
    tier_order,
    trace_argv,
)


def caps(**kw) -> Capabilities:
    base = dict(os_name="Linux", icmp_dgram=False, icmp_raw=False, icmp_win_api=False)
    base.update(kw)
    return Capabilities(**base)


def test_tier_order_puts_mtr_first_when_available():
    order = tier_order(caps(mtr_binary="/usr/bin/mtr", icmp_dgram=True, traceroute_binary="/usr/bin/traceroute"))
    assert order == ["mtr_json", "icmplib", "system_traceroute"]


def test_tier_order_on_windows_uses_the_win_api_before_the_binary():
    order = tier_order(caps(os_name="Windows", icmp_win_api=True, traceroute_binary="C:\\tracert.exe"))
    assert order == ["icmp_win", "system_traceroute"]


def test_tier_order_on_windows_still_prefers_mtr_if_someone_installed_it():
    order = tier_order(caps(os_name="Windows", mtr_binary="C:\\mtr.exe", icmp_win_api=True))
    assert order[0] == "mtr_json"
    assert order[1] == "icmp_win"


def test_tier_order_without_any_icmp_falls_back_to_the_system_binary():
    assert tier_order(caps(traceroute_binary="/usr/bin/traceroute")) == ["system_traceroute"]


def test_tier_order_with_nothing_available_is_empty():
    assert tier_order(caps()) == []


def good(name: str) -> TraceResult:
    return TraceResult(target="1.1.1.1", backend=name, hops=[TraceHop(ttl=1, ip="192.168.1.1")], completed=True)


async def test_cascade_uses_the_first_tier_that_works():
    calls: list[str] = []

    async def tier1() -> TraceResult:
        calls.append("t1")
        return good("mtr_json")

    async def tier2() -> TraceResult:
        calls.append("t2")
        return good("icmplib")

    result = await run_cascade([("mtr_json", tier1), ("icmplib", tier2)])
    assert result.backend == "mtr_json"
    assert calls == ["t1"]


async def test_cascade_falls_through_when_a_tier_raises():
    calls: list[str] = []

    async def tier1() -> TraceResult:
        calls.append("t1")
        raise FileNotFoundError("mtr not on PATH")

    async def tier2() -> TraceResult:
        calls.append("t2")
        return good("icmplib")

    result = await run_cascade([("mtr_json", tier1), ("icmplib", tier2)])
    assert result.backend == "icmplib"
    assert calls == ["t1", "t2"]


async def test_cascade_falls_through_when_a_tier_returns_no_hops():
    async def tier1() -> TraceResult:
        return TraceResult(target="1.1.1.1", backend="mtr_json", hops=[])

    async def tier2() -> TraceResult:
        return good("system_traceroute")

    result = await run_cascade([("mtr_json", tier1), ("system_traceroute", tier2)])
    assert result.backend == "system_traceroute"


async def test_cascade_tries_every_tier_in_order():
    calls: list[str] = []

    def failing(name: str):
        async def tier() -> TraceResult:
            calls.append(name)
            raise OSError(name)

        return tier

    async def last() -> TraceResult:
        calls.append("system")
        return good("system_traceroute")

    result = await run_cascade(
        [("mtr_json", failing("mtr")), ("icmp_win", failing("win")), ("icmplib", failing("lib")), ("system_traceroute", last)]
    )
    assert calls == ["mtr", "win", "lib", "system"]
    assert result.backend == "system_traceroute"


async def test_cascade_exhaustion_yields_a_none_backend_not_an_exception():
    async def boom() -> TraceResult:
        raise OSError("nope")

    result = await run_cascade([("mtr_json", boom), ("icmplib", boom)])
    assert isinstance(result, TraceResult)
    assert result.backend == "none"
    assert result.hops == []
    assert result.completed is False


async def test_cascade_with_no_tiers_at_all_yields_a_none_backend():
    result = await run_cascade([])
    assert result.backend == "none"


async def test_cascade_never_swallows_cancellation():
    async def cancelled() -> TraceResult:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_cascade([("mtr_json", cancelled)])


def test_tcp_trace_is_absent_unless_it_is_asked_for():
    assert "tcp_trace" not in tier_order(caps(icmp_dgram=True, traceroute_binary="/usr/bin/traceroute"))
    assert "tcp_trace" not in tier_order(caps(os_name="Windows", icmp_win_api=True))


def test_tcp_trace_leads_the_cascade_when_requested():
    order = tier_order(caps(mtr_binary="/usr/bin/mtr", icmp_dgram=True), tcp_trace=True)
    assert order[0] == "tcp_trace"
    assert order[1:] == ["mtr_json", "icmplib"]


def test_tcp_trace_can_be_the_only_tier():
    assert tier_order(caps(), tcp_trace=True) == ["tcp_trace"]


def test_win_replies_become_hops_with_ttl_expiry_handled():
    replies = [
        (1, IcmpReply(address="192.168.1.1", status=IP_TTL_EXPIRED_TRANSIT, rtt_ms=1.0, ttl=64)),
        (2, IcmpReply(address=None, status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)),
        (3, IcmpReply(address="1.1.1.1", status=IP_SUCCESS, rtt_ms=12.0, ttl=57)),
    ]
    hops = hops_from_win_replies(replies)
    assert [h.ttl for h in hops] == [1, 2, 3]
    assert hops[0].ip == "192.168.1.1"
    assert hops[0].probes == [1.0]
    assert hops[1].ip is None
    assert hops[1].probes == [None]
    assert hops[1].loss_pct == 100.0
    assert hops[2].ip == "1.1.1.1"
    assert hops[2].avg_ms == 12.0


async def test_run_in_daemon_thread_returns_the_function_result():
    result = await _run_in_daemon_thread(lambda a, b: a + b, 2, 3)
    assert result == 5


async def test_run_in_daemon_thread_propagates_exceptions():
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError, match="nope"):
        await _run_in_daemon_thread(boom)


def test_run_in_daemon_thread_never_creates_a_non_daemon_worker_thread():
    # This is the crux of the process-exit hang fix: asyncio.to_thread()/the
    # default executor spawn non-daemon ThreadPoolExecutor workers that get
    # joined by concurrent.futures' atexit handler, which is exactly what let
    # an orphaned, uncancellable IcmpSendEcho2 call keep the whole process
    # alive. We can't unit-test "process exit is never blocked" directly (that
    # needs a real subprocess), but we can pin the one property that makes it
    # true: every thread this helper spawns is a plain daemon thread, never
    # routed through a ThreadPoolExecutor.
    seen: list[threading.Thread] = []
    original_init = threading.Thread.__init__

    def spy_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        seen.append(self)

    async def run():
        await _run_in_daemon_thread(lambda: None)

    threading.Thread.__init__ = spy_init
    try:
        asyncio.run(run())
    finally:
        threading.Thread.__init__ = original_init

    assert seen
    assert all(t.daemon for t in seen)


def test_filter_trace_tiers_drops_windows_tracert_when_a_v4_bind_is_forced():
    kept, dropped = filter_trace_tiers(["icmp_win", "system_traceroute"], "Windows", forced_v4=True)
    assert kept == ["icmp_win"]
    assert dropped == ["system_traceroute"]


def test_filter_trace_tiers_keeps_everything_when_nothing_is_forced():
    order = ["icmp_win", "system_traceroute"]
    kept, dropped = filter_trace_tiers(order, "Windows", forced_v4=False)
    assert kept == order
    assert dropped == []


def test_filter_trace_tiers_leaves_unix_traceroute_alone_even_when_forced():
    order = ["mtr_json", "icmplib", "system_traceroute"]
    kept, dropped = filter_trace_tiers(order, "Linux", forced_v4=True)
    assert kept == order
    assert dropped == []


def test_filter_trace_tiers_is_a_noop_when_system_traceroute_is_absent():
    kept, dropped = filter_trace_tiers(["icmp_win"], "Windows", forced_v4=True)
    assert kept == ["icmp_win"]
    assert dropped == []


def test_trace_argv_mtr_adds_address_flag_when_source_given():
    args = trace_argv("mtr_json", "/usr/bin/mtr", "1.1.1.1", max_hops=30, cycles=10, os_name="Linux", source_ip="192.168.1.34")
    assert args == [
        "/usr/bin/mtr", "--json", "--report-cycles", "10", "--max-ttl", "30",
        "--address", "192.168.1.34", "1.1.1.1",
    ]


def test_trace_argv_mtr_omits_address_flag_without_a_source():
    args = trace_argv("mtr_json", "/usr/bin/mtr", "1.1.1.1", max_hops=30, cycles=10, os_name="Linux")
    assert "--address" not in args


def test_trace_argv_unix_traceroute_adds_source_flag():
    args = trace_argv(
        "system_traceroute", "/usr/bin/traceroute", "1.1.1.1", max_hops=30, cycles=1,
        os_name="Linux", source_ip="192.168.1.34",
    )
    assert args == ["/usr/bin/traceroute", "-m", "30", "-w", "2", "-s", "192.168.1.34", "1.1.1.1"]


def test_trace_argv_windows_tracert_never_gets_a_source_flag():
    args = trace_argv(
        "system_traceroute", "tracert", "1.1.1.1", max_hops=30, cycles=1,
        os_name="Windows", source_ip="192.168.1.34",
    )
    assert args == ["tracert", "-h", "30", "-w", "2", "1.1.1.1"]
    assert "-s" not in args and "-S" not in args
