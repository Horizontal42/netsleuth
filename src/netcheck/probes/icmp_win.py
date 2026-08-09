from __future__ import annotations

import struct
from typing import NamedTuple

IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013

_UNREACHABLE = {IP_DEST_NET_UNREACHABLE, IP_DEST_HOST_UNREACHABLE, 11001, 11004}
_HEAD = struct.Struct("<4BIIHH")


class IcmpReply(NamedTuple):
    address: str | None
    status: int
    rtt_ms: float | None
    ttl: int


def classify_status(status: int) -> str:
    if status == IP_SUCCESS:
        return "ok"
    if status == IP_TTL_EXPIRED_TRANSIT:
        return "ttl_expired"
    if status == IP_REQ_TIMED_OUT:
        return "timeout"
    if status in _UNREACHABLE:
        return "unreachable"
    return "error"


def parse_echo_reply(buffer: bytes, pointer_size: int = 8) -> IcmpReply:
    # Layout after the fixed head: the Data pointer is aligned to its own width,
    # then IP_OPTION_INFORMATION starts with Ttl as its first byte.
    head_size = _HEAD.size
    padding = (-head_size) % pointer_size
    ttl_offset = head_size + padding + pointer_size
    if len(buffer) < ttl_offset + 1:
        return IcmpReply(address=None, status=-1, rtt_ms=None, ttl=0)
    a, b, c, d, status, rtt, _data_size, _reserved = _HEAD.unpack_from(buffer, 0)
    ttl = buffer[ttl_offset]
    if status in (IP_REQ_TIMED_OUT,) or (a, b, c, d) == (0, 0, 0, 0):
        return IcmpReply(address=None, status=status, rtt_ms=None, ttl=ttl)
    return IcmpReply(address=f"{a}.{b}.{c}.{d}", status=status, rtt_ms=float(rtt), ttl=ttl)


import ctypes
import platform
import socket
import time

_REPLY_BUFFER_SIZE = 4096
_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    from ctypes import wintypes


class _IpOptionInformation(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


def win_icmp_available() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        ctypes.WinDLL("Iphlpapi.dll")
    except OSError:
        return False
    return True


def _handle():
    if not _IS_WINDOWS:
        raise OSError("icmp_win backend is only available on Windows")
    iphlpapi = ctypes.WinDLL("Iphlpapi.dll")
    iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
    # argtypes must be declared for HANDLE-typed args: ctypes otherwise
    # marshals a bare int as a 32-bit C int and overflows on a 64-bit handle.
    iphlpapi.IcmpSendEcho2.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint16,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    iphlpapi.IcmpSendEcho2.restype = ctypes.c_uint32
    iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    handle = iphlpapi.IcmpCreateFile()
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("IcmpCreateFile failed")
    return iphlpapi, handle


def echo_once(dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netcheck") -> IcmpReply:
    iphlpapi, handle = _handle()
    try:
        options = _IpOptionInformation(Ttl=ttl, Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
        buffer = ctypes.create_string_buffer(_REPLY_BUFFER_SIZE)
        address = struct.unpack("<I", socket.inet_aton(dest))[0]
        count = iphlpapi.IcmpSendEcho2(
            handle,
            None,
            None,
            None,
            ctypes.c_uint32(address),
            payload,
            ctypes.c_ushort(len(payload)),
            ctypes.byref(options),
            buffer,
            ctypes.c_uint32(_REPLY_BUFFER_SIZE),
            ctypes.c_uint32(timeout_ms),
        )
        if count == 0:
            return IcmpReply(address=None, status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)
        return parse_echo_reply(buffer.raw, pointer_size=ctypes.sizeof(ctypes.c_void_p))
    finally:
        iphlpapi.IcmpCloseHandle(handle)


def ping_samples_win(host: str, count: int, interval: float, timeout: float) -> list[float | None]:
    dest = socket.gethostbyname(host)
    timeout_ms = int(timeout * 1000)
    samples: list[float | None] = []
    for index in range(count):
        if index:
            time.sleep(interval)
        reply = echo_once(dest, ttl=128, timeout_ms=timeout_ms)
        samples.append(reply.rtt_ms if classify_status(reply.status) == "ok" else None)
    return samples


# A single non-responding hop must never be allowed to eat the whole trace budget:
# cap its timeout even if that leaves room for very few hops.
_MAX_HOP_TIMEOUT_MS = 4000


def trace_hops_win(dest: str, max_hops: int, timeout_ms: int) -> list[tuple[int, IcmpReply]]:
    # timeout_ms is the TOTAL budget for the whole trace (all hops combined), not
    # a per-hop timeout - a caller-supplied 60s budget across 30 hops must not turn
    # into 30 minutes of blocking IcmpSendEcho2 calls.
    address = socket.gethostbyname(dest)
    hops: list[tuple[int, IcmpReply]] = []
    per_hop_timeout_ms = max(1, min(timeout_ms // max(max_hops, 1), _MAX_HOP_TIMEOUT_MS))
    deadline = time.monotonic() + timeout_ms / 1000.0
    for ttl in range(1, max_hops + 1):
        if time.monotonic() >= deadline:
            break
        reply = echo_once(address, ttl=ttl, timeout_ms=per_hop_timeout_ms)
        hops.append((ttl, reply))
        if classify_status(reply.status) == "ok":
            break
    return hops
