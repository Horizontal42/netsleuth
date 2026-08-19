from __future__ import annotations

from netsleuth.models import Capabilities
from netsleuth.netinfo import (
    choose_latency_backend,
    choose_trace_backend,
    degradation_note,
)


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


from netsleuth.netinfo import detect_capabilities
from unittest.mock import patch

def test_detect_capabilities_linux_happy_path():
    with patch("netsleuth.netinfo.platform.system", return_value="Linux"), \
         patch("netsleuth.netinfo._is_elevated", return_value=True), \
         patch("netsleuth.netinfo._socket_works", side_effect=[True, True]), \
         patch("netsleuth.netinfo._win_icmp_available", return_value=False), \
         patch("netsleuth.netinfo.shutil.which", side_effect=lambda x: "/usr/bin/" + x):

        c = detect_capabilities()

        assert c.os_name == "Linux"
        assert c.is_elevated is True
        assert c.icmp_dgram is True
        assert c.icmp_raw is True
        assert c.icmp_win_api is False
        assert c.mtr_binary == "/usr/bin/mtr"
        assert c.traceroute_binary == "/usr/bin/traceroute"


def test_detect_capabilities_windows_happy_path():
    with patch("netsleuth.netinfo.platform.system", return_value="Windows"), \
         patch("netsleuth.netinfo._is_elevated", return_value=False), \
         patch("netsleuth.netinfo._socket_works", return_value=False), \
         patch("netsleuth.netinfo._win_icmp_available", return_value=True), \
         patch("netsleuth.netinfo.shutil.which", side_effect=lambda x: "C:\\Windows\\System32\\" + x + ".exe"):

        c = detect_capabilities()

        assert c.os_name == "Windows"
        assert c.is_elevated is False
        assert c.icmp_dgram is False
        assert c.icmp_raw is False
        assert c.icmp_win_api is True
        assert c.mtr_binary == "C:\\Windows\\System32\\mtr.exe"
        assert c.traceroute_binary == "C:\\Windows\\System32\\tracert.exe"

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

from netsleuth.netinfo import iface_for_ip, is_tunnel_iface, mtu_anomaly


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


import socket

from netsleuth.netinfo import _parse_windows_default_gateway

_ROUTE_PRINT_WITH_A_VPN_ADAPTER = """
===========================================================================
Interface List
 12...00 15 5d 01 ab cd ......Ethernet
 15...00 ff 21 4a bc de ......Radmin VPN
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        26.0.0.1        26.0.0.5     35
          0.0.0.0          0.0.0.0      192.168.3.1    192.168.3.72     25
         26.0.0.0        255.0.0.0         On-link         26.0.0.5    291
     192.168.3.0    255.255.255.0         On-link     192.168.3.72    281
===========================================================================
Persistent Routes:
  None
"""


def test_windows_default_gateway_picks_the_lowest_metric_route_not_the_first_listed():
    # Radmin VPN's 0.0.0.0 route (metric 35) is listed before the real Ethernet
    # default (metric 25); Windows itself prefers the lower metric for outbound
    # traffic, so the parser must too, regardless of listing order.
    assert (
        _parse_windows_default_gateway(_ROUTE_PRINT_WITH_A_VPN_ADAPTER, socket.AF_INET) == "192.168.3.1"
    )


def test_windows_default_gateway_returns_the_only_route_when_there_is_one():
    single = """
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.34     25
"""
    assert _parse_windows_default_gateway(single, socket.AF_INET) == "192.168.1.1"


def test_windows_default_gateway_returns_none_when_no_default_route_exists():
    assert _parse_windows_default_gateway("Active Routes:\nNone\n", socket.AF_INET) is None

from dataclasses import dataclass

@dataclass
class MockAddr:
    family: int
    address: str

@dataclass
class MockStats:
    mtu: int

from unittest.mock import patch
from netsleuth.netinfo import collect_local_net
from netsleuth.models import LocalNet

@patch("netsleuth.netinfo.primary_interface_ip")
@patch("netsleuth.netinfo.psutil.net_if_addrs")
@patch("netsleuth.netinfo.psutil.net_if_stats")
@patch("netsleuth.netinfo._default_gateway")
@patch("netsleuth.netinfo._resolvers_per_adapter")
def test_collect_local_net_happy_path(mock_resolvers, mock_gw, mock_stats, mock_addrs, mock_ip):
    # Setup mocks
    mock_ip.side_effect = ["192.168.1.50", "2001:db8::1"]
    mock_addrs.return_value = {
        "eth0": [MockAddr(family=socket.AF_INET, address="192.168.1.50"), MockAddr(family=socket.AF_INET6, address="2001:db8::1")]
    }
    mock_stats.return_value = {"eth0": MockStats(mtu=1500)}
    mock_gw.side_effect = ["192.168.1.1", "fe80::1"]
    mock_resolvers.return_value = {"eth0": ["1.1.1.1", "8.8.8.8"]}

    result = collect_local_net()

    assert result.iface_name == "eth0"
    assert result.local_ipv4 == "192.168.1.50"
    assert result.local_ipv6 == "2001:db8::1"
    assert result.iface_mtu == 1500
    assert result.default_gateway_v4 == "192.168.1.1"
    assert result.default_gateway_v6 == "fe80::1"
    assert result.dns_servers_per_adapter == {"eth0": ["1.1.1.1", "8.8.8.8"]}
    assert result.is_dual_stack is True
    assert result.cgnat is False
    assert result.cgnat_evidence is None

@patch("netsleuth.netinfo.primary_interface_ip")
@patch("netsleuth.netinfo.psutil.net_if_addrs")
@patch("netsleuth.netinfo.psutil.net_if_stats")
@patch("netsleuth.netinfo._default_gateway")
@patch("netsleuth.netinfo._resolvers_per_adapter")
def test_collect_local_net_cgnat_on_local_ip(mock_resolvers, mock_gw, mock_stats, mock_addrs, mock_ip):
    mock_ip.side_effect = ["100.64.1.2", None]
    mock_addrs.return_value = {
        "eth0": [MockAddr(family=socket.AF_INET, address="100.64.1.2")]
    }
    mock_stats.return_value = {"eth0": MockStats(mtu=1500)}
    mock_gw.side_effect = ["100.64.1.1", None]
    mock_resolvers.return_value = {}

    result = collect_local_net()

    assert result.cgnat is True
    assert "100.64.1.2" in result.cgnat_evidence

@patch("netsleuth.netinfo.primary_interface_ip")
@patch("netsleuth.netinfo.psutil.net_if_addrs")
@patch("netsleuth.netinfo.psutil.net_if_stats")
@patch("netsleuth.netinfo._default_gateway")
@patch("netsleuth.netinfo._resolvers_per_adapter")
def test_collect_local_net_cgnat_on_gateway(mock_resolvers, mock_gw, mock_stats, mock_addrs, mock_ip):
    mock_ip.side_effect = ["192.168.1.50", None]
    mock_addrs.return_value = {
        "eth0": [MockAddr(family=socket.AF_INET, address="192.168.1.50")]
    }
    mock_stats.return_value = {"eth0": MockStats(mtu=1500)}
    mock_gw.side_effect = ["100.64.1.1", None]
    mock_resolvers.return_value = {}

    result = collect_local_net()

    assert result.cgnat is True
    assert "100.64.1.1" in result.cgnat_evidence

@patch("netsleuth.netinfo.primary_interface_ip")
@patch("netsleuth.netinfo.psutil.net_if_addrs")
@patch("netsleuth.netinfo.psutil.net_if_stats")
@patch("netsleuth.netinfo._default_gateway")
@patch("netsleuth.netinfo._resolvers_per_adapter")
def test_collect_local_net_no_network(mock_resolvers, mock_gw, mock_stats, mock_addrs, mock_ip):
    mock_ip.side_effect = [None, None]
    mock_addrs.return_value = {}
    mock_stats.return_value = {}
    mock_gw.side_effect = [None, None]
    mock_resolvers.return_value = {}

    result = collect_local_net()

    assert result.iface_name is None
    assert result.local_ipv4 is None
    assert result.local_ipv6 is None
    assert result.iface_mtu is None
    assert result.default_gateway_v4 is None
    assert result.default_gateway_v6 is None
    assert result.is_dual_stack is False
    assert result.cgnat is False
