from __future__ import annotations

import ipaddress
import socket

from netsleuth.models import BindTarget
from netsleuth.netinfo import iface_for_ip


def usable_addresses(addrs: list[tuple[int, str]]) -> tuple[str | None, str | None]:
    v4 = v6 = None
    for family, address in addrs:
        if family == socket.AF_INET and v4 is None:
            if not ipaddress.IPv4Address(address).is_loopback and not address.startswith("169.254."):
                v4 = address
        elif family == socket.AF_INET6 and v6 is None:
            zone_free = address.split("%")[0]
            parsed = ipaddress.IPv6Address(zone_free)
            if not parsed.is_loopback and not parsed.is_link_local:
                v6 = zone_free
    return v4, v6


def _match_iface_name(requested: str, names: list[str]) -> str | list[str]:
    if requested in names:
        return requested
    lowered = requested.lower()
    exact_ci = [n for n in names if n.lower() == lowered]
    if len(exact_ci) == 1:
        return exact_ci[0]
    substring = [n for n in names if lowered in n.lower()]
    if len(substring) == 1:
        return substring[0]
    return substring or exact_ci


def resolve_bind_target(
    requested: str,
    addrs_by_iface: dict[str, list[tuple[int, str]]],
    up_by_iface: dict[str, bool],
) -> BindTarget:
    try:
        ip = str(ipaddress.ip_address(requested))
    except ValueError:
        ip = None

    if ip is not None:
        iface_name = iface_for_ip(ip, addrs_by_iface)
        if iface_name is None:
            return BindTarget(requested=requested, error=f"no adapter has the address {requested!r}")
    else:
        match = _match_iface_name(requested, list(addrs_by_iface))
        if isinstance(match, list):
            hint = available_interfaces_hint(addrs_by_iface, up_by_iface)
            if not match:
                return BindTarget(requested=requested, error=f"no adapter matches {requested!r}.\n{hint}")
            return BindTarget(
                requested=requested,
                error=f"{requested!r} matches multiple adapters: {', '.join(match)}. Be more specific.",
            )
        iface_name = match

    is_up = up_by_iface.get(iface_name, False)
    v4, v6 = usable_addresses(addrs_by_iface.get(iface_name, []))
    if not is_up:
        return BindTarget(requested=requested, iface_name=iface_name, is_up=False, error=f"adapter {iface_name!r} is down")
    if v4 is None and v6 is None:
        return BindTarget(
            requested=requested,
            iface_name=iface_name,
            is_up=is_up,
            error=f"adapter {iface_name!r} has no usable (routable) address",
        )
    return BindTarget(requested=requested, iface_name=iface_name, ipv4=v4, ipv6=v6, is_up=is_up)


def available_interfaces_hint(
    addrs_by_iface: dict[str, list[tuple[int, str]]],
    up_by_iface: dict[str, bool],
) -> str:
    lines = ["Available adapters:"]
    for name, addrs in addrs_by_iface.items():
        v4, v6 = usable_addresses(addrs)
        state = "up" if up_by_iface.get(name, False) else "down"
        ips = ", ".join(a for a in (v4, v6) if a) or "no usable address"
        lines.append(f"  {name} ({state}): {ips}")
    return "\n".join(lines)
