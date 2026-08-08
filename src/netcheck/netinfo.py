from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import socket
import subprocess

import psutil

from netcheck.models import Capabilities, LocalNet

_TUNNEL_PATTERNS = (
    re.compile(r"^(tun|tap|utun|ppp|wg|nordlynx|proton|ipsec|gpd)\d*", re.IGNORECASE),
    re.compile(r"wireguard", re.IGNORECASE),
    re.compile(r"tap-windows", re.IGNORECASE),
    re.compile(r"openvpn", re.IGNORECASE),
)

_UNIX_REMEDY = (
    "ICMP is unavailable without privileges, so latency was measured by TCP connect timing "
    "(a different metric: 'loss' means connection failures, not dropped packets). "
    "Remedy: sysctl -w net.ipv4.ping_group_range='0 2147483647'"
)
_WINDOWS_REMEDY = (
    "ICMP is unavailable, so latency was measured by TCP connect timing "
    "(a different metric: 'loss' means connection failures, not dropped packets). "
    "Remedy: the Iphlpapi.dll IcmpSendEcho2 API is normally always present; a host firewall "
    "or security product is blocking it."
)


def choose_latency_backend(caps: Capabilities) -> str:
    if caps.icmp_win_api:
        return "icmp_win"
    if caps.icmp_dgram:
        return "icmp_dgram"
    if caps.icmp_raw:
        return "icmp_raw"
    return "tcp"


def choose_trace_backend(caps: Capabilities) -> str:
    if caps.mtr_binary:
        return "mtr_json"
    if caps.icmp_win_api:
        return "icmp_win"
    if caps.icmp_dgram or caps.icmp_raw:
        return "icmplib"
    if caps.traceroute_binary:
        return "system_traceroute"
    return "none"


def degradation_note(caps: Capabilities) -> str | None:
    if choose_latency_backend(caps) != "tcp":
        return None
    return _WINDOWS_REMEDY if caps.os_name == "Windows" else _UNIX_REMEDY


def _is_elevated() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _socket_works(family: int, sock_type: int, proto: int) -> bool:
    try:
        sock = socket.socket(family, sock_type, proto)
    except (OSError, AttributeError, PermissionError):
        return False
    sock.close()
    return True


def _win_icmp_available() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        ctypes.WinDLL("Iphlpapi.dll")
    except OSError:
        return False
    return True


def detect_capabilities() -> Capabilities:
    os_name = platform.system()
    caps = Capabilities(
        os_name=os_name,
        is_elevated=_is_elevated(),
        icmp_dgram=_socket_works(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP),
        icmp_raw=_socket_works(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
        icmp_win_api=_win_icmp_available(),
        mtr_binary=shutil.which("mtr"),
        traceroute_binary=shutil.which("tracert") if os_name == "Windows" else shutil.which("traceroute"),
    )
    caps.chosen_latency_backend = choose_latency_backend(caps)
    caps.chosen_trace_backend = choose_trace_backend(caps)
    note = degradation_note(caps)
    if note:
        caps.notes.append(note)
    return caps


def is_tunnel_iface(name: str) -> bool:
    return any(pattern.search(name) for pattern in _TUNNEL_PATTERNS)


def iface_for_ip(ip: str, addrs_by_iface: dict[str, list[tuple[int, str]]]) -> str | None:
    for iface, addrs in addrs_by_iface.items():
        for _family, address in addrs:
            if address == ip:
                return iface
    return None


def mtu_anomaly(mtu: int | None) -> str | None:
    if mtu is None or mtu >= 1500:
        return None
    if 1405 <= mtu <= 1440:
        return "wireguard"
    if 1350 <= mtu <= 1404:
        return "ipsec"
    return "small"


def primary_interface_ip(target: str = "1.1.1.1", family: int = socket.AF_INET) -> str | None:
    # Connecting a UDP socket sends nothing; it only asks the kernel which local
    # address the route to `target` would use. This is the reliable way to pick
    # the *active* interface when several are up.
    probe = "2606:4700:4700::1111" if family == socket.AF_INET6 else target
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.connect((probe, 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _resolvers_per_adapter() -> dict[str, list[str]]:
    if platform.system() == "Windows":
        return _resolvers_windows()
    return _resolvers_unix()


def _resolvers_windows() -> dict[str, list[str]]:
    script = (
        "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | "
        "ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    adapters: dict[str, list[str]] = {}
    for line in out.splitlines():
        if "|" not in line:
            continue
        alias, _, servers = line.partition("|")
        found = [s.strip() for s in servers.split(",") if s.strip()]
        if found:
            adapters.setdefault(alias.strip(), []).extend(found)
    return adapters


def _resolvers_unix() -> dict[str, list[str]]:
    adapters: dict[str, list[str]] = {}
    try:
        text = open("/etc/resolv.conf", encoding="utf-8", errors="replace").read()
    except OSError:
        text = ""
    servers = [line.split()[1] for line in text.splitlines() if line.startswith("nameserver") and len(line.split()) > 1]
    if servers:
        adapters["system"] = servers
    try:
        scutil = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, errors="replace", timeout=15
        ).stdout
    except (OSError, subprocess.SubprocessError):
        scutil = ""
    current = None
    for line in scutil.splitlines():
        stripped = line.strip()
        if stripped.startswith("if_index"):
            current = stripped.split("(")[-1].rstrip(")") or None
        elif stripped.startswith("nameserver[") and current:
            adapters.setdefault(current, []).append(stripped.split(":", 1)[1].strip())
    return adapters


def collect_local_net() -> LocalNet:
    v4 = primary_interface_ip()
    v6 = primary_interface_ip(family=socket.AF_INET6)
    addrs_by_iface = {
        name: [(a.family, a.address.split("%")[0]) for a in addrs]
        for name, addrs in psutil.net_if_addrs().items()
    }
    iface = iface_for_ip(v4, addrs_by_iface) if v4 else None
    stats = psutil.net_if_stats()
    return LocalNet(
        iface_name=iface,
        local_ipv4=v4,
        local_ipv6=v6,
        iface_mtu=stats[iface].mtu if iface and iface in stats else None,
        default_gateway_v4=_default_gateway(socket.AF_INET),
        default_gateway_v6=_default_gateway(socket.AF_INET6),
        dns_servers_per_adapter=_resolvers_per_adapter(),
        is_dual_stack=bool(v4 and v6),
    )


def _default_gateway(family: int) -> str | None:
    if platform.system() == "Windows":
        args = ["route", "print", "-6" if family == socket.AF_INET6 else "-4"]
        needle = "::/0" if family == socket.AF_INET6 else "0.0.0.0"
    else:
        args = ["ip", "-6", "route", "show", "default"] if family == socket.AF_INET6 else ["ip", "route", "show", "default"]
        needle = "via"
    try:
        out = subprocess.run(
            args, capture_output=True, text=True, errors="replace", timeout=15
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if needle not in line:
            continue
        tokens = line.split()
        if needle == "via" and "via" in tokens:
            return tokens[tokens.index("via") + 1]
        candidates = [t for t in tokens if _looks_like_ip(t)]
        if len(candidates) >= 3:
            return candidates[2]
    return None


def _looks_like_ip(token: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, token)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, token)
        return True
    except OSError:
        return False
