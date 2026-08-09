from __future__ import annotations

import asyncio
import inspect

import pytest

from netsleuth.models import PortProbe
from netsleuth.probes.dpi_check import (
    check_dpi,
    classify_connect_outcome,
    dpi_verdict,
    probe_port,
)

_CYRILLIC = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")


def has_cyrillic(text: str) -> bool:
    return any(ch in _CYRILLIC for ch in text.lower())


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (None, "open"),
        (ConnectionResetError(), "reset"),
        (ConnectionRefusedError(), "closed"),
        (TimeoutError(), "filtered"),
        (OSError(), "error"),
    ],
)
def test_classify_connect_outcome(exc, expected):
    assert classify_connect_outcome(exc) == expected


def test_dpi_verdict_clean_when_all_open_or_closed():
    ports = [
        PortProbe(port=80, state="open"),
        PortProbe(port=443, state="closed"),
    ]
    verdict, rationale, rationale_ru = dpi_verdict(ports)
    assert verdict == "clean"
    assert rationale
    assert has_cyrillic(rationale_ru)


def test_dpi_verdict_reset_injection_when_reset_seen_among_open():
    ports = [
        PortProbe(port=80, state="open"),
        PortProbe(port=443, state="reset"),
    ]
    verdict, rationale, rationale_ru = dpi_verdict(ports)
    assert verdict == "reset_injection"
    assert has_cyrillic(rationale_ru)


def test_dpi_verdict_partial_filtering_for_mixed_open_and_filtered():
    ports = [
        PortProbe(port=80, state="open"),
        PortProbe(port=443, state="filtered"),
    ]
    verdict, rationale, rationale_ru = dpi_verdict(ports)
    assert verdict == "partial_filtering"
    assert has_cyrillic(rationale_ru)


def test_dpi_verdict_unreachable_when_all_filtered_is_cautious_about_cause():
    ports = [
        PortProbe(port=80, state="filtered"),
        PortProbe(port=443, state="filtered"),
    ]
    verdict, rationale, rationale_ru = dpi_verdict(ports)
    assert verdict == "unreachable"
    assert "or" in rationale.lower()
    assert "или" in rationale_ru


def test_dpi_verdict_unreachable_when_ports_empty():
    verdict, rationale, rationale_ru = dpi_verdict([])
    assert verdict == "unreachable"
    assert "or" in rationale.lower()
    assert "или" in rationale_ru


@pytest.mark.parametrize(
    "verdict_ports",
    [
        [PortProbe(port=80, state="open")],
        [PortProbe(port=80, state="reset"), PortProbe(port=443, state="open")],
        [PortProbe(port=80, state="filtered"), PortProbe(port=443, state="open")],
        [PortProbe(port=80, state="filtered")],
        [],
    ],
)
def test_dpi_verdict_rationale_ru_always_nonempty_and_cyrillic(verdict_ports):
    _verdict, _rationale, rationale_ru = dpi_verdict(verdict_ports)
    assert rationale_ru
    assert has_cyrillic(rationale_ru)


def test_port_probe_rejects_unknown_state():
    with pytest.raises(ValueError):
        PortProbe(port=443, state="bogus")


def test_check_dpi_refuses_a_target_that_was_not_explicitly_provided():
    sig = inspect.signature(check_dpi)
    assert sig.parameters["target"].default is inspect.Parameter.empty
    assert sig.parameters["resolved_ip"].default is inspect.Parameter.empty


@pytest.mark.asyncio
async def test_probe_port_reports_open_then_closed_on_same_loopback_port():
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    open_probe = await probe_port("127.0.0.1", port, timeout=2.0)
    assert open_probe.state == "open"

    server.close()
    await server.wait_closed()

    # Windows loopback quirk: the first SYN to a just-closed port is dropped and
    # ECONNREFUSED only surfaces after the ~2s retransmit timer fires, so this
    # needs headroom above 2s to stay deterministic (Linux resolves near-instantly).
    closed_probe = await probe_port("127.0.0.1", port, timeout=5.0)
    assert closed_probe.state == "closed"


@pytest.mark.asyncio
async def test_check_dpi_produces_a_probe_per_port_with_a_consistent_verdict():
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]

    closed_server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    closed_port = closed_server.sockets[0].getsockname()[1]
    closed_server.close()
    await closed_server.wait_closed()

    result = await check_dpi(
        "example.test",
        "127.0.0.1",
        [open_port, closed_port],
        timeout=5.0,
        delay=0.0,
        concurrency=2,
    )

    server.close()
    await server.wait_closed()

    assert result.target == "example.test"
    assert result.resolved_ip == "127.0.0.1"
    assert result.consented is True
    assert len(result.ports) == 2

    expected_verdict, expected_rationale, expected_rationale_ru = dpi_verdict(result.ports)
    assert result.verdict == expected_verdict
    assert result.rationale == expected_rationale
    assert result.rationale_ru == expected_rationale_ru
