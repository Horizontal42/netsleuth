from __future__ import annotations

import pytest

from netcheck.traceparse import parse_linux


@pytest.fixture()
def basic(trace_fixture):
    return parse_linux(trace_fixture("linux", "gnu_basic.txt"))


def test_linux_hop_count_ignores_the_header_line(basic):
    assert [hop.ttl for hop in basic] == [1, 2, 3, 4, 5, 6]


def test_linux_extracts_reverse_dns_and_ip(basic):
    assert basic[0].ip == "192.168.1.1"
    assert basic[0].reverse_dns == "_gateway"
    assert basic[3].ip == "77.88.1.5"
    assert basic[3].reverse_dns == "ae-1.r01.ams.example.net"


def test_linux_bare_ip_hop_has_no_reverse_dns(basic):
    assert basic[1].ip == "10.64.0.1"
    assert basic[1].reverse_dns is None


def test_linux_probe_values_are_floats_in_order(basic):
    assert basic[0].probes == [1.234, 1.102, 1.045]
    assert basic[3].probes == [12.004, 11.883, 12.111]


def test_linux_full_timeout_hop_has_three_none_probes_and_no_ip(basic):
    hop = basic[2]
    assert hop.probes == [None, None, None]
    assert hop.ip is None
    assert hop.loss_pct == 100.0
    assert hop.avg_ms is None


def test_linux_partial_timeout_hop_keeps_probe_positions(basic):
    hop = basic[4]
    assert hop.probes == [None, 13.402, None]
    assert hop.loss_pct == pytest.approx(66.667)
    assert hop.avg_ms == 13.402


def test_linux_computes_per_hop_statistics(basic):
    hop = basic[0]
    assert hop.min_ms == 1.045
    assert hop.max_ms == 1.234
    assert hop.avg_ms == pytest.approx(1.127, abs=0.001)
    assert hop.jitter_ms == pytest.approx(0.095, abs=0.001)


def test_linux_captures_unreachable_annotations(trace_fixture):
    hops = parse_linux(trace_fixture("linux", "gnu_unreachable.txt"))
    assert hops[1].annotations == ["!N"]
    assert hops[2].annotations == ["!H"]
    assert hops[1].probes == [8.2, 8.3, 8.25]


def test_linux_max_hops_run_yields_trailing_dead_hops(trace_fixture):
    hops = parse_linux(trace_fixture("linux", "gnu_maxhops.txt"))
    assert len(hops) == 5
    assert all(h.ip is None for h in hops[1:])
    assert all(h.loss_pct == 100.0 for h in hops[1:])


def test_linux_parser_tolerates_empty_and_garbage_input():
    assert parse_linux("") == []
    assert parse_linux("bash: traceroute: command not found\n") == []
