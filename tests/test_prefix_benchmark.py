from __future__ import annotations

from netsleuth.models import Capabilities, PingResult, PrefixProbe
from netsleuth.probes.prefix_benchmark import (
    benchmark_prefixes,
    first_host,
    rank,
    select_prefixes,
    summarize,
)


def test_first_host_returns_dot_one_for_slash_24():
    assert first_host("203.0.113.0/24") == "203.0.113.1"


def test_first_host_returns_dot_one_for_slash_22():
    assert first_host("203.0.112.0/22") == "203.0.112.1"


def test_first_host_returns_dot_one_for_slash_16():
    assert first_host("203.0.0.0/16") == "203.0.0.1"


def test_first_host_returns_none_for_slash_31():
    assert first_host("203.0.113.0/31") is None


def test_first_host_returns_none_for_slash_32():
    assert first_host("203.0.113.5/32") is None


def test_first_host_returns_none_for_invalid_prefix():
    assert first_host("not-a-prefix") is None


def test_first_host_returns_none_when_offset_exceeds_network():
    assert first_host("203.0.113.0/24", offset=500) is None


def test_select_prefixes_drops_invalid_strings_silently():
    result = select_prefixes(["not-a-prefix", "1.1.1.0/24"], limit=32)
    assert result == ["1.1.1.0/24"]


def test_select_prefixes_filters_ipv6_when_family_is_4():
    result = select_prefixes(["1.1.1.0/24", "2606:4700::/32"], limit=32, family=4)
    assert result == ["1.1.1.0/24"]


def test_select_prefixes_filters_ipv4_when_family_is_6():
    result = select_prefixes(["1.1.1.0/24", "2606:4700::/32"], limit=32, family=6)
    assert result == ["2606:4700::/32"]


def test_select_prefixes_drops_private_reserved_and_cgnat():
    result = select_prefixes(
        ["10.0.0.0/8", "192.168.1.0/24", "100.64.0.0/10", "1.1.1.0/24"],
        limit=32,
    )
    assert result == ["1.1.1.0/24"]


def test_select_prefixes_dedups_equivalent_networks():
    result = select_prefixes(["1.1.1.0/24", "1.1.1.0/24"], limit=32)
    assert result == ["1.1.1.0/24"]


def test_select_prefixes_respects_limit():
    prefixes = [f"1.1.{i}.0/24" for i in range(5)]
    result = select_prefixes(prefixes, limit=2)
    assert len(result) == 2


def test_select_prefixes_is_deterministic_across_calls():
    prefixes = ["1.1.4.0/24", "1.1.1.0/24", "1.1.3.0/24", "1.1.2.0/24"]
    first = select_prefixes(prefixes, limit=32)
    second = select_prefixes(list(reversed(prefixes)), limit=32)
    assert first == second
    assert first == sorted(first)


def test_rank_puts_unreachable_last_even_with_avg_ms():
    reachable = PrefixProbe(prefix="1.1.1.0/24", avg_ms=50.0, reachable=True)
    fake_unreachable = PrefixProbe(prefix="1.1.2.0/24", avg_ms=5.0, reachable=False)
    result = rank([fake_unreachable, reachable])
    assert [p.prefix for p in result] == ["1.1.1.0/24", "1.1.2.0/24"]


def test_rank_sorts_reachable_ascending_by_avg_ms():
    slow = PrefixProbe(prefix="1.1.2.0/24", avg_ms=80.0, reachable=True)
    fast = PrefixProbe(prefix="1.1.1.0/24", avg_ms=10.0, reachable=True)
    unreachable = PrefixProbe(prefix="1.1.3.0/24", avg_ms=None, reachable=False)
    result = rank([slow, unreachable, fast])
    assert [p.prefix for p in result] == ["1.1.1.0/24", "1.1.2.0/24", "1.1.3.0/24"]


def test_summarize_handles_empty_results_without_dividing_by_zero():
    benchmark = summarize(None, 0, [])
    assert benchmark.method == "none"
    assert benchmark.best is None
    assert benchmark.worst is None
    assert benchmark.spread_ms is None
    assert benchmark.results == []


def test_summarize_picks_best_and_worst_with_single_reachable_result():
    probe = PrefixProbe(prefix="1.1.1.0/24", avg_ms=42.0, reachable=True)
    benchmark = summarize("64500", 10, [probe])
    assert benchmark.method == "icmp"
    assert benchmark.best == "1.1.1.0/24"
    assert benchmark.worst == "1.1.1.0/24"
    assert benchmark.spread_ms is None


def test_summarize_computes_spread_with_two_reachable_results():
    fast = PrefixProbe(prefix="1.1.1.0/24", avg_ms=10.0, reachable=True)
    slow = PrefixProbe(prefix="1.1.2.0/24", avg_ms=30.0, reachable=True)
    benchmark = summarize("64500", 10, [slow, fast])
    assert benchmark.best == "1.1.1.0/24"
    assert benchmark.worst == "1.1.2.0/24"
    assert benchmark.spread_ms == 20.0


async def test_benchmark_prefixes_probes_selected_hosts_with_mocked_ping_host(monkeypatch):
    async def fake_ping_host(host, label, count, interval, timeout, backend, source_ip=None, semaphore=None):
        return PingResult(
            label=label,
            host=host,
            resolved_ip=host,
            method="tcp",
            sent=count,
            received=count,
            loss_pct=0.0,
            avg_ms=10.0,
        )

    monkeypatch.setattr("netsleuth.probes.prefix_benchmark.ping_host", fake_ping_host)

    prefixes = [f"1.1.{i}.0/24" for i in range(5)]
    caps = Capabilities()

    benchmark = await benchmark_prefixes(
        prefixes,
        caps,
        limit=3,
        count=1,
        interval=0.0,
        timeout=0.5,
        concurrency=2,
    )

    assert benchmark.prefixes_probed <= 3
    assert len(benchmark.results) == benchmark.prefixes_probed
    assert all(p.reachable for p in benchmark.results)
    assert benchmark.method == "icmp"
