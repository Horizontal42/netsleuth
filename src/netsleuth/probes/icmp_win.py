from __future__ import annotations

import ctypes
import platform
import socket
import struct
import time
from typing import NamedTuple

IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013

_UNREACHABLE = {IP_DEST_NET_UNREACHABLE, IP_DEST_HOST_UNREACHABLE, 11001, 11004}
_HEAD = struct.Struct("<4BIIHH")

_REPLY_BUFFER_SIZE = 4096
_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    from ctypes import wintypes


class IcmpReply(NamedTuple):
    """ICMP echo reply data.
    
    Attributes:
        address: Responder IP address or None
        status: Windows ICMP status code
        rtt_ms: Round-trip time in milliseconds or None
        ttl: Time-to-live value
    """
    address: str | None
    status: int
    rtt_ms: float | None
    ttl: int


def classify_status(status: int) -> str:
    """Classify ICMP status code into human-readable category.
    
    Args:
        status: Windows ICMP status code
        
    Returns:
        One of: 'ok', 'ttl_expired', 'timeout', 'unreachable', 'error'
    """
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
    """Parse Windows ICMP echo reply buffer.
    
    Layout after the fixed head: the Data pointer is aligned to its own width,
    then IP_OPTION_INFORMATION starts with Ttl as its first byte.
    
    Args:
        buffer: Raw buffer from IcmpSendEcho2
        pointer_size: Size of pointer on current architecture (4 or 8)
        
    Returns:
        IcmpReply with parsed data
    """
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


class _IpOptionInformation(ctypes.Structure):
    """Windows IP option information structure for ICMP."""
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


def win_icmp_available() -> bool:
    """Check if Windows ICMP API is available.
    
    Returns:
        True if running on Windows with Iphlpapi.dll available
    """
    if platform.system() != "Windows":
        return False
    try:
        ctypes.WinDLL("Iphlpapi.dll")
    except OSError:
        return False
    return True


def _handle():
    """Create and configure Windows ICMP handle.
    
    Returns:
        Tuple of (iphlpapi DLL, handle)
        
    Raises:
        OSError: If not running on Windows or handle creation fails
    """
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
    # Ex variant inserts SourceAddress (IPAddr) before DestinationAddress; only
    # used when a caller asks to bind to a specific adapter's address.
    iphlpapi.IcmpSendEcho2Ex.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint16,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    iphlpapi.IcmpSendEcho2Ex.restype = ctypes.c_uint32
    iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    handle = iphlpapi.IcmpCreateFile()
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("IcmpCreateFile failed")
    return iphlpapi, handle


def echo_once(
    dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netsleuth", source_ip: str | None = None
) -> IcmpReply:
    """Send single ICMP echo request and parse reply.
    
    Args:
        dest: Destination IP address
        ttl: Time-to-live value
        timeout_ms: Timeout in milliseconds
        payload: Echo payload bytes
        source_ip: Optional source IP to bind to
        
    Returns:
        IcmpReply with response data
    """
    iphlpapi, handle = _handle()
    try:
        options = _IpOptionInformation(Ttl=ttl, Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
        buffer = ctypes.create_string_buffer(_REPLY_BUFFER_SIZE)
        address = struct.unpack("<I", socket.inet_aton(dest))[0]
        if source_ip:
            source = struct.unpack("<I", socket.inet_aton(source_ip))[0]
            count = iphlpapi.IcmpSendEcho2Ex(
                handle,
                None,
                None,
                None,
                ctypes.c_uint32(source),
                ctypes.c_uint32(address),
                payload,
                ctypes.c_ushort(len(payload)),
                ctypes.byref(options),
                buffer,
                ctypes.c_uint32(_REPLY_BUFFER_SIZE),
                ctypes.c_uint32(timeout_ms),
            )
        else:
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


def ping_samples_win(
    host: str, count: int, interval: float, timeout: float, source_ip: str | None = None
) -> list[float | None]:
    """Perform series of pings on Windows.
    
    Args:
        host: Target hostname or IP
        count: Number of pings to send
        interval: Time between pings in seconds
        timeout: Per-ping timeout in seconds
        source_ip: Optional source IP to bind to
        
    Returns:
        List of RTT values in ms (None for timeouts)
    """
    dest = socket.gethostbyname(host)
    timeout_ms = int(timeout * 1000)
    samples: list[float | None] = []
    for index in range(count):
        if index:
            time.sleep(interval)
        reply = echo_once(dest, ttl=128, timeout_ms=timeout_ms, source_ip=source_ip)
        samples.append(reply.rtt_ms if classify_status(reply.status) == "ok" else None)
    return samples


# A single non-responding hop must never be allowed to eat the whole trace budget:
# cap its timeout even if that leaves room for very few hops.
_MAX_HOP_TIMEOUT_MS = 4000


def trace_hops_win(
    dest: str, max_hops: int, timeout_ms: int, source_ip: str | None = None
) -> list[tuple[int, IcmpReply]]:
    """Perform Windows ICMP traceroute.
    
    timeout_ms is the TOTAL budget for the whole trace (all hops combined), not
    a per-hop timeout - a caller-supplied 60s budget across 30 hops must not turn
    into 30 minutes of blocking IcmpSendEcho2 calls.
    
    Args:
        dest: Target hostname or IP
        max_hops: Maximum TTL/hops to probe
        timeout_ms: Total timeout budget for entire trace in milliseconds
        source_ip: Optional source IP to bind to
        
    Returns:
        List of (ttl, IcmpReply) tuples for each hop
    """
    address = socket.gethostbyname(dest)
    hops: list[tuple[int, IcmpReply]] = []
    per_hop_timeout_ms = max(1, min(timeout_ms // max(max_hops, 1), _MAX_HOP_TIMEOUT_MS))
    deadline = time.monotonic() + timeout_ms / 1000.0
    for ttl in range(1, max_hops + 1):
        if time.monotonic() >= deadline:
            break
        reply = echo_once(address, ttl=ttl, timeout_ms=per_hop_timeout_ms, source_ip=source_ip)
        hops.append((ttl, reply))
        if classify_status(reply.status) == "ok":
            break
    return hops
