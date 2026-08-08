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


import pytest

from netcheck.netinfo import iface_for_ip, is_tunnel_iface, mtu_anomaly


def test_iface_for_ip_matches_the_owning_adapter():
    addrs = {
        "lo": [(2, "127.0.0.1")],
        "eth0": [(2, "192.168.1.34"), (23, "fe80::1")],
        "wg0": [(2, "10.7.0.2")],
    }
    assert iface_for_ip("192.168.1.34", addrs) == "eth0"
    assert iface_for_ip("10.7.0.2", addrs) == "wg0"
    assert iface_for_ip("203.0.113.1", addrs) is None


@pytest.mark.parametrize(
    "name",
    ["tun0", "tap0", "wg0", "utun3", "ppp0", "WireGuard Tunnel", "TAP-Windows Adapter V9", "nordlynx"],
)
def test_tunnel_interfaces_are_recognised(name):
    assert is_tunnel_iface(name) is True


@pytest.mark.parametrize("name", ["eth0", "en0", "Wi-Fi", "Ethernet 2", "lo", "Loopback Pseudo-Interface 1"])
def test_ordinary_interfaces_are_not_flagged_as_tunnels(name):
    assert is_tunnel_iface(name) is False


def test_mtu_anomaly_recognises_wireguard_and_ipsec_sizes():
    assert mtu_anomaly(1420) == "wireguard"
    assert mtu_anomaly(1412) == "wireguard"
    assert mtu_anomaly(1400) == "ipsec"
    assert mtu_anomaly(1380) == "ipsec"


def test_mtu_anomaly_ignores_normal_and_unknown_values():
    assert mtu_anomaly(1500) is None
    assert mtu_anomaly(9000) is None
    assert mtu_anomaly(None) is None


def test_mtu_anomaly_flags_unusually_small_links_generically():
    assert mtu_anomaly(1200) == "small"
