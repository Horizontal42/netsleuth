from __future__ import annotations

from netcheck.models import Capabilities
from netcheck.netinfo import choose_latency_backend, choose_trace_backend, degradation_note


def caps(**kw) -> Capabilities:
    base = dict(os_name="Linux", is_elevated=False, icmp_dgram=False, icmp_raw=False, icmp_win_api=False)
    base.update(kw)
    return Capabilities(**base)


def test_windows_prefers_the_win32_icmp_api_over_everything():
    c = caps(os_name="Windows", icmp_win_api=True, icmp_dgram=True, icmp_raw=True)
    assert choose_latency_backend(c) == "icmp_win"


def test_unix_prefers_unprivileged_datagram_icmp():
    assert choose_latency_backend(caps(icmp_dgram=True, icmp_raw=True)) == "icmp_dgram"


def test_unix_falls_back_to_raw_icmp_when_datagram_is_unavailable():
    assert choose_latency_backend(caps(icmp_raw=True, is_elevated=True)) == "icmp_raw"


def test_latency_falls_back_to_tcp_when_no_icmp_is_possible():
    assert choose_latency_backend(caps()) == "tcp"


def test_trace_backend_prefers_mtr_when_the_binary_exists():
    c = caps(mtr_binary="/usr/bin/mtr", icmp_dgram=True, traceroute_binary="/usr/bin/traceroute")
    assert choose_trace_backend(c) == "mtr_json"


def test_trace_backend_uses_win_api_before_the_system_binary():
    c = caps(os_name="Windows", icmp_win_api=True, traceroute_binary="C:\\Windows\\System32\\TRACERT.EXE")
    assert choose_trace_backend(c) == "icmp_win"


def test_trace_backend_uses_icmplib_on_unix_before_the_system_binary():
    c = caps(icmp_dgram=True, traceroute_binary="/usr/bin/traceroute")
    assert choose_trace_backend(c) == "icmplib"


def test_trace_backend_falls_back_to_the_system_binary():
    assert choose_trace_backend(caps(traceroute_binary="/usr/bin/traceroute")) == "system_traceroute"


def test_trace_backend_reports_none_when_nothing_is_available():
    assert choose_trace_backend(caps()) == "none"


def test_degradation_note_is_absent_when_icmp_works():
    assert degradation_note(caps(icmp_dgram=True, traceroute_binary="/usr/bin/traceroute")) is None


def test_degradation_note_explains_the_tcp_fallback_with_a_remedy():
    note = degradation_note(caps())
    assert note is not None
    assert "TCP" in note
    assert "ping_group_range" in note


def test_degradation_note_on_windows_mentions_the_api_rather_than_sysctl():
    note = degradation_note(caps(os_name="Windows"))
    assert note is not None
    assert "Iphlpapi" in note
