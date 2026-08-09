from __future__ import annotations

import pytest

from netsleuth.models import TraceHop
from netsleuth.traceparse import parse_linux, finalize_hop


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


from netsleuth.traceparse import WINDOWS_SUB_MS, parse_windows


@pytest.fixture()
def win_en(trace_fixture):
    return parse_windows(trace_fixture("windows", "tracert_en.txt"))


def test_windows_hop_numbers_and_count(win_en):
    assert [hop.ttl for hop in win_en] == [1, 2, 3, 4, 5]


def test_windows_sub_millisecond_probe_is_not_dropped(win_en):
    assert win_en[0].probes == [1.0, WINDOWS_SUB_MS, 1.0]
    assert 0.0 < WINDOWS_SUB_MS < 1.0


def test_windows_bracketed_ip_and_hostname_are_split(win_en):
    assert win_en[3].ip == "77.88.1.5"
    assert win_en[3].reverse_dns == "ae-1.r01.ams.example.net"


def test_windows_bare_ip_hop_has_no_reverse_dns(win_en):
    assert win_en[1].ip == "10.64.0.1"
    assert win_en[1].reverse_dns is None


def test_windows_timed_out_hop_is_detected_by_shape_not_by_message(win_en):
    hop = win_en[2]
    assert hop.probes == [None, None, None]
    assert hop.ip is None
    assert hop.loss_pct == 100.0


def test_windows_partial_timeout_keeps_probe_order(win_en):
    assert win_en[4].probes == [14.0, None, 13.0]
    assert win_en[4].ip == "1.1.1.1"


def test_windows_headers_and_footer_are_not_parsed_as_hops(win_en):
    assert all(hop.ttl <= 5 for hop in win_en)
    assert len(win_en) == 5


def test_windows_cp866_localized_output_parses_identically(trace_fixture):
    ru = parse_windows(trace_fixture("windows", "tracert_ru_cp866.txt", encoding="cp866"))
    en = parse_windows(trace_fixture("windows", "tracert_en.txt"))
    assert [h.ttl for h in ru] == [h.ttl for h in en]
    assert [h.ip for h in ru] == [h.ip for h in en]
    assert [h.probes for h in ru] == [h.probes for h in en]


def test_windows_cp866_timed_out_hop_has_no_spurious_ip(trace_fixture):
    ru = parse_windows(trace_fixture("windows", "tracert_ru_cp866.txt", encoding="cp866"))
    assert ru[2].ip is None
    assert ru[2].probes == [None, None, None]


def test_windows_destination_unreachable_hop_keeps_its_ip(trace_fixture):
    hops = parse_windows(trace_fixture("windows", "tracert_unreachable_en.txt"))
    assert hops[-1].ttl == 3
    assert hops[-1].ip == "198.51.100.7"
    assert hops[-1].probes == []
    assert hops[-1].loss_pct == 0.0


def test_windows_parser_tolerates_empty_input():
    assert parse_windows("") == []


from netsleuth.traceparse import parse_darwin


def test_darwin_basic_hops_match_the_gnu_shape(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_basic.txt"))
    assert [h.ttl for h in hops] == [1, 2, 3, 4, 5]
    assert hops[0].ip == "192.168.1.1"
    assert hops[0].reverse_dns is None
    assert hops[3].reverse_dns == "ae-1.r01.ams.example.net"
    assert hops[2].probes == [None, None, None]


def test_darwin_merges_continuation_lines_into_one_hop(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert [h.ttl for h in hops] == [1, 2, 3, 4, 5]
    hop = hops[1]
    assert hop.probes == [9.001, 9.22, 8.87]
    assert hop.ip == "10.64.0.1"


def test_darwin_records_alternate_addresses_for_a_multipath_hop(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert "alt:10.64.0.5" in hops[1].annotations
    assert "alt:10.64.0.1" not in hops[1].annotations


def test_darwin_keeps_bsd_only_annotations(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert hops[3].annotations == ["!H"]
    assert hops[4].annotations == ["!X"]


def test_darwin_partial_timeout_hop_keeps_positions(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert hops[2].probes == [None, 11.2, None]
    assert hops[2].loss_pct == pytest.approx(66.667)


def test_darwin_parser_tolerates_empty_input():
    assert parse_darwin("") == []


from unittest.mock import patch

from netsleuth.models import TraceConfig
from netsleuth.traceparse import build_trace_result, parse_traceroute


def test_parse_traceroute_routes_to_windows():
    with patch("netsleuth.traceparse.parse_windows") as mock_windows:
        parse_traceroute("test text", "Windows")
        mock_windows.assert_called_once_with("test text")


def test_parse_traceroute_routes_to_darwin():
    with patch("netsleuth.traceparse.parse_darwin") as mock_darwin:
        parse_traceroute("test text", "Darwin")
        mock_darwin.assert_called_once_with("test text")


def test_parse_traceroute_routes_to_linux_for_linux():
    with patch("netsleuth.traceparse.parse_linux") as mock_linux:
        parse_traceroute("test text", "Linux")
        mock_linux.assert_called_once_with("test text")


def test_parse_traceroute_routes_to_linux_for_unknown_os():
    with patch("netsleuth.traceparse.parse_linux") as mock_linux:
        parse_traceroute("test text", "SunOS")
        mock_linux.assert_called_once_with("test text")


def test_dispatcher_routes_by_os_name(trace_fixture):
    win = parse_traceroute(trace_fixture("windows", "tracert_en.txt"), "Windows")
    lin = parse_traceroute(trace_fixture("linux", "gnu_basic.txt"), "Linux")
    mac = parse_traceroute(trace_fixture("darwin", "bsd_basic.txt"), "Darwin")
    assert win[0].probes[1] == 0.5
    assert lin[0].probes == [1.234, 1.102, 1.045]
    assert mac[0].probes == [2.145, 1.902, 1.87]


def test_dispatcher_defaults_unknown_os_to_the_gnu_parser(trace_fixture):
    hops = parse_traceroute(trace_fixture("linux", "gnu_basic.txt"), "SunOS")
    assert [h.ttl for h in hops] == [1, 2, 3, 4, 5, 6]


def test_build_trace_result_marks_completion_when_the_target_is_reached(trace_fixture):
    result = build_trace_result(
        trace_fixture("linux", "gnu_basic.txt"),
        "Linux",
        TraceConfig(
            target="1.1.1.1",
            resolved_ip="1.1.1.1",
            max_hops=30,
        ),
    )
    assert result.completed is True
    assert result.max_hops_reached is False
    assert result.backend == "system_traceroute"
    assert result.cycles == 1
    assert len(result.hops) == 6


def test_build_trace_result_flags_a_run_that_died_at_max_hops(trace_fixture):
    result = build_trace_result(
        trace_fixture("linux", "gnu_maxhops.txt"),
        "Linux",
        TraceConfig(
            target="203.0.113.200",
            resolved_ip="203.0.113.200",
            max_hops=5,
        ),
    )
    assert result.completed is False
    assert result.max_hops_reached is True


def test_build_trace_result_is_not_complete_when_the_last_hop_is_a_different_host(trace_fixture):
    result = build_trace_result(
        trace_fixture("linux", "gnu_unreachable.txt"),
        "Linux",
        TraceConfig(
            target="203.0.113.9",
            resolved_ip="203.0.113.9",
            max_hops=30,
        ),
    )
    assert result.completed is False
    assert result.max_hops_reached is False


def test_build_trace_result_on_empty_output_is_a_well_formed_empty_result():
    result = build_trace_result("", "Linux", TraceConfig(target="1.1.1.1", resolved_ip=None))
    assert result.hops == []
    assert result.completed is False
    assert result.max_hops_reached is False

def test_finalize_hop_computes_stats_for_probes():
    hop = TraceHop(ttl=1, probes=[10.0, 20.0, 30.0])
    finalized = finalize_hop(hop)
    assert finalized is hop
    assert finalized.loss_pct == 0.0
    assert finalized.min_ms == 10.0
    assert finalized.avg_ms == 20.0
    assert finalized.max_ms == 30.0
    assert finalized.jitter_ms == 10.0

def test_finalize_hop_handles_empty_probes():
    hop = TraceHop(ttl=1, probes=[])
    finalized = finalize_hop(hop)
    assert finalized.loss_pct == 0.0
    assert finalized.min_ms is None
    assert finalized.avg_ms is None
    assert finalized.max_ms is None
    assert finalized.jitter_ms is None

def test_finalize_hop_handles_all_lost_probes():
    hop = TraceHop(ttl=1, probes=[None, None, None])
    finalized = finalize_hop(hop)
    assert finalized.loss_pct == 100.0
    assert finalized.min_ms is None
    assert finalized.avg_ms is None
    assert finalized.max_ms is None
    assert finalized.jitter_ms is None

def test_finalize_hop_handles_partial_lost_probes():
    hop = TraceHop(ttl=1, probes=[10.0, None, 20.0])
    finalized = finalize_hop(hop)
    assert finalized.loss_pct == pytest.approx(33.333, abs=0.01)
    assert finalized.min_ms == 10.0
    assert finalized.avg_ms == 15.0
    assert finalized.max_ms == 20.0
    assert finalized.jitter_ms == 0.0
