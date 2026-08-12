from __future__ import annotations

import struct

import pytest

from netsleuth.probes.icmp_win import (
    IP_DEST_HOST_UNREACHABLE,
    IP_PACKET_TOO_BIG,
    IP_REQ_TIMED_OUT,
    IP_SUCCESS,
    IP_TTL_EXPIRED_TRANSIT,
    classify_status,
    parse_echo_reply,
)


def make_reply(address: str, status: int, rtt: int, ttl: int, pointer_size: int = 8) -> bytes:
    # ICMP_ECHO_REPLY: IPAddr(4) Status(4) RoundTripTime(4) DataSize(2) Reserved(2)
    # then a pointer (Data), then IP_OPTION_INFORMATION { Ttl Tos Flags OptionsSize }
    # followed by another pointer. Both pointers are alignment-padded to their width.
    packed = struct.pack("<4B", *(int(o) for o in address.split(".")))
    head = packed + struct.pack("<IIHH", status, rtt, 32, 0)
    head += b"\x00" * (pointer_size - (len(head) % pointer_size) if len(head) % pointer_size else 0)
    head += b"\x00" * pointer_size
    head += struct.pack("<4B", ttl, 0, 0, 0)
    head += b"\x00" * (pointer_size - 4 if pointer_size > 4 else 0)
    head += b"\x00" * pointer_size
    return head


def test_parses_a_successful_reply_on_64_bit():
    reply = parse_echo_reply(make_reply("1.1.1.1", IP_SUCCESS, 12, 57), pointer_size=8)
    assert reply.address == "1.1.1.1"
    assert reply.status == IP_SUCCESS
    assert reply.rtt_ms == 12.0
    assert reply.ttl == 57


def test_parses_a_successful_reply_on_32_bit():
    reply = parse_echo_reply(make_reply("8.8.4.4", IP_SUCCESS, 9, 120, pointer_size=4), pointer_size=4)
    assert reply.address == "8.8.4.4"
    assert reply.rtt_ms == 9.0
    assert reply.ttl == 120


def test_address_bytes_are_read_in_network_order():
    reply = parse_echo_reply(make_reply("192.168.1.34", IP_SUCCESS, 1, 64))
    assert reply.address == "192.168.1.34"


def test_a_ttl_expired_reply_keeps_the_intermediate_router_address():
    reply = parse_echo_reply(make_reply("10.64.0.1", IP_TTL_EXPIRED_TRANSIT, 8, 253))
    assert reply.address == "10.64.0.1"
    assert reply.status == IP_TTL_EXPIRED_TRANSIT
    assert reply.rtt_ms == 8.0


def test_a_timed_out_reply_has_no_address_and_no_rtt():
    reply = parse_echo_reply(make_reply("0.0.0.0", IP_REQ_TIMED_OUT, 0, 0))
    assert reply.address is None
    assert reply.rtt_ms is None
    assert reply.status == IP_REQ_TIMED_OUT


def test_a_truncated_buffer_is_reported_as_an_error_not_an_exception():
    reply = parse_echo_reply(b"\x01\x02")
    assert reply.address is None
    assert reply.rtt_ms is None
    assert reply.status == -1


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (IP_SUCCESS, "ok"),
        (IP_TTL_EXPIRED_TRANSIT, "ttl_expired"),
        (IP_REQ_TIMED_OUT, "timeout"),
        (IP_DEST_HOST_UNREACHABLE, "unreachable"),
        (IP_PACKET_TOO_BIG, "packet_too_big"),
        (-1, "error"),
        (11050, "error"),
    ],
)
def test_status_classification(status, expected):
    assert classify_status(status) == expected
