from __future__ import annotations

import ctypes
import os
import platform
import shutil
import socket

from netcheck.models import Capabilities

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
