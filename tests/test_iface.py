from __future__ import annotations

import socket

from netsleuth.iface import available_interfaces_hint, resolve_bind_target, usable_addresses


def addrs(**kw) -> dict[str, list[tuple[int, str]]]:
    return kw


def up(**kw) -> dict[str, bool]:
    return kw


def test_usable_addresses_picks_first_non_loopback_v4_and_v6():
    v4, v6 = usable_addresses(
        [
            (socket.AF_INET, "127.0.0.1"),
            (socket.AF_INET, "192.168.1.34"),
            (socket.AF_INET6, "::1"),
            (socket.AF_INET6, "fe80::1"),
            (socket.AF_INET6, "2001:db8::1"),
        ]
    )
    assert v4 == "192.168.1.34"
    assert v6 == "2001:db8::1"


def test_usable_addresses_rejects_apipa_v4():
    v4, v6 = usable_addresses([(socket.AF_INET, "169.254.1.2")])
    assert v4 is None
    assert v6 is None


def test_usable_addresses_rejects_link_local_v6():
    v4, v6 = usable_addresses([(socket.AF_INET6, "fe80::1")])
    assert v6 is None


def test_usable_addresses_accepts_link_local_only_when_nothing_else_present():
    # A link-local-only adapter (typical for an interface with no DHCP/global
    # IPv6) is a real, common case, not an error -- it just means ipv6=None.
    v4, v6 = usable_addresses([(socket.AF_INET, "192.168.1.34"), (socket.AF_INET6, "fe80::1")])
    assert v4 == "192.168.1.34"
    assert v6 is None


def test_resolve_bind_target_by_exact_name():
    result = resolve_bind_target(
        "Ethernet",
        addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")], VPN=[(socket.AF_INET, "10.0.0.5")]),
        up(Ethernet=True, VPN=True),
    )
    assert result.iface_name == "Ethernet"
    assert result.ipv4 == "192.168.3.72"
    assert result.error is None


def test_resolve_bind_target_by_ip_finds_owning_adapter():
    result = resolve_bind_target(
        "192.168.3.72",
        addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")]),
        up(Ethernet=True),
    )
    assert result.iface_name == "Ethernet"
    assert result.ipv4 == "192.168.3.72"


def test_resolve_bind_target_exact_name_beats_substring_match():
    result = resolve_bind_target(
        "Ethernet",
        addrs(
            Ethernet=[(socket.AF_INET, "192.168.3.72")],
            **{"vEthernet (Default Switch)": [(socket.AF_INET, "172.20.0.1")]},
        ),
        up(**{"Ethernet": True, "vEthernet (Default Switch)": True}),
    )
    assert result.iface_name == "Ethernet"


def test_resolve_bind_target_case_insensitive_exact_match():
    result = resolve_bind_target(
        "ethernet",
        addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")]),
        up(Ethernet=True),
    )
    assert result.iface_name == "Ethernet"


def test_resolve_bind_target_unique_substring_match():
    result = resolve_bind_target(
        "radmin",
        addrs(**{"Radmin VPN": [(socket.AF_INET, "26.0.0.5")]}),
        up(**{"Radmin VPN": True}),
    )
    assert result.iface_name == "Radmin VPN"


def test_resolve_bind_target_ambiguous_substring_is_an_error():
    result = resolve_bind_target(
        "eth",
        addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")], **{"Ethernet 2": [(socket.AF_INET, "10.0.0.9")]}),
        up(Ethernet=True, **{"Ethernet 2": True}),
    )
    assert result.error is not None
    assert "Ethernet" in result.error and "Ethernet 2" in result.error


def test_resolve_bind_target_unknown_name_is_an_error_listing_candidates():
    result = resolve_bind_target("Nope", addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")]), up(Ethernet=True))
    assert result.error is not None
    assert "Ethernet" in result.error


def test_resolve_bind_target_down_adapter_is_an_error():
    result = resolve_bind_target(
        "Ethernet", addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")]), up(Ethernet=False)
    )
    assert result.error is not None
    assert result.is_up is False


def test_resolve_bind_target_apipa_only_adapter_is_an_error():
    result = resolve_bind_target(
        "PdaNet", addrs(PdaNet=[(socket.AF_INET, "169.254.1.2")]), up(PdaNet=True)
    )
    assert result.error is not None


def test_resolve_bind_target_ipv6_comes_from_the_same_matched_adapter():
    result = resolve_bind_target(
        "Ethernet",
        addrs(Ethernet=[(socket.AF_INET, "192.168.3.72"), (socket.AF_INET6, "2001:db8::1")]),
        up(Ethernet=True),
    )
    assert result.ipv4 == "192.168.3.72"
    assert result.ipv6 == "2001:db8::1"


def test_available_interfaces_hint_lists_every_adapter_with_its_state():
    hint = available_interfaces_hint(
        addrs(Ethernet=[(socket.AF_INET, "192.168.3.72")], PdaNet=[(socket.AF_INET, "169.254.1.2")]),
        up(Ethernet=True, PdaNet=False),
    )
    assert "Ethernet" in hint
    assert "192.168.3.72" in hint
    assert "PdaNet" in hint
    assert "down" in hint.lower()
