from __future__ import annotations

import asyncio

import pytest

from netcheck.models import Capabilities, TraceHop, TraceResult
from netcheck.probes.icmp_win import IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, IcmpReply
from netcheck.probes.traceroute import hops_from_win_replies, run_cascade, tier_order


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
