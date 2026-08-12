from __future__ import annotations

import pytest

from netsleuth.config import Thresholds
from netsleuth.interpret import quic_findings
from netsleuth.models import QuicResult
from netsleuth.probes.quic_rtt import quic_verdict


def test_quic_verdict_ok_when_quic_succeeds():
    assert quic_verdict(quic_ok=True, tcp_ok=True) == "ok"


def test_quic_verdict_ok_even_if_tcp_state_is_unknown():
    assert quic_verdict(quic_ok=True, tcp_ok=False) == "ok"


def test_quic_verdict_blocked_when_quic_fails_but_tcp_succeeds():
    assert quic_verdict(quic_ok=False, tcp_ok=True) == "blocked"


def test_quic_verdict_unreachable_when_both_fail():
    assert quic_verdict(quic_ok=False, tcp_ok=False) == "unreachable"


def quic(**kw) -> QuicResult:
    base = dict(label="cloudflare", host="cloudflare.com", port=443)
    base.update(kw)
    return QuicResult(**base)


@pytest.fixture()
def thresholds() -> Thresholds:
    return Thresholds()


def test_quic_findings_silent_on_a_healthy_result(thresholds):
    assert quic_findings([quic(handshake_ms=50.0, tcp_rtt_ms=20.0)], thresholds) == []


def test_quic_findings_flags_blocked_quic_with_working_tcp(thresholds):
    findings = quic_findings([quic(error="timeout", tcp_rtt_ms=20.0)], thresholds)
    assert [f.id for f in findings] == ["quic.blocked.cloudflare"]
    assert findings[0].severity == "warn"


def test_quic_findings_silent_when_both_quic_and_tcp_fail(thresholds):
    # a fully dead host is latency_findings' job (latency.unreachable), not quic's.
    assert quic_findings([quic(error="timeout", tcp_rtt_ms=None)], thresholds) == []


def test_quic_findings_flags_a_slow_handshake(thresholds):
    findings = quic_findings([quic(handshake_ms=500.0, tcp_rtt_ms=20.0)], thresholds)
    assert [f.id for f in findings] == ["quic.handshake_slow.cloudflare"]


def test_quic_findings_fast_handshake_produces_nothing(thresholds):
    findings = quic_findings([quic(handshake_ms=50.0, tcp_rtt_ms=20.0)], thresholds)
    assert findings == []


aioquic = pytest.importorskip("aioquic")


async def test_measure_quic_reports_an_error_for_an_unreachable_host():
    from netsleuth.probes.quic_rtt import measure_quic

    result = await measure_quic("dead", "192.0.2.1", port=1, timeout=0.5)
    assert result.label == "dead"
    assert result.error
    assert result.handshake_ms is None


async def test_quic_fanout_returns_a_result_per_target():
    from netsleuth.probes.quic_rtt import quic_fanout

    results = await quic_fanout([("a", "192.0.2.1"), ("b", "192.0.2.2")], port=1, timeout=0.5, concurrency=2)
    assert len(results) == 2
    assert all(r.error for r in results)
