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
