from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from netsleuth.probes.tls_rtt import (
    cert_name,
    cpu_bound_ratio,
    days_remaining,
    fingerprint_verdict,
    measure_tls,
    split_timings,
    tls_context,
    tls_fanout,
)


def _closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_split_timings_derives_handshake_from_total_minus_tcp():
    tcp_rtt, handshake, ttfb = split_timings(20.0, 50.0, 100.0)
    assert tcp_rtt == 20.0
    assert handshake == 30.0
    assert ttfb == 100.0


def test_split_timings_handshake_is_none_when_total_is_missing():
    tcp_rtt, handshake, ttfb = split_timings(20.0, None, 100.0)
    assert tcp_rtt == 20.0
    assert handshake is None
    assert ttfb == 100.0


def test_split_timings_clamps_a_negative_delta_to_zero():
    _tcp_rtt, handshake, _ttfb = split_timings(50.0, 40.0, None)
    assert handshake == 0.0


def test_cpu_bound_ratio_divides_handshake_by_tcp_rtt():
    assert cpu_bound_ratio(30.0, 15.0) == 2.0


def test_cpu_bound_ratio_is_none_when_tcp_rtt_is_missing():
    assert cpu_bound_ratio(30.0, None) is None


def test_cpu_bound_ratio_is_none_when_tcp_rtt_is_zero():
    assert cpu_bound_ratio(30.0, 0.0) is None


def test_tls_context_verifies_by_default():
    ctx = tls_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_tls_context_disables_verification_when_asked():
    ctx = tls_context(verify=False)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


def test_fingerprint_verdict_matches_case_and_colon_insensitively():
    pins = {"example.com": "AA:BB:CC:DD"}
    assert fingerprint_verdict("example.com", "aabbccdd", pins) == "match"


def test_fingerprint_verdict_mismatch():
    pins = {"example.com": "aabbccdd"}
    assert fingerprint_verdict("example.com", "11223344", pins) == "mismatch"


def test_fingerprint_verdict_unpinned_when_host_has_no_pin():
    assert fingerprint_verdict("example.com", "aabbccdd", {}) == "unpinned"


def test_fingerprint_verdict_mismatch_when_actual_is_none():
    assert fingerprint_verdict("example.com", None, {"example.com": "aabbccdd"}) == "mismatch"


def test_cert_name_flattens_the_rdn_sequence():
    subject = ((("commonName", "example.com"),), (("organizationName", "Example Inc"),))
    assert cert_name(subject) == "commonName=example.com, organizationName=Example Inc"


def test_cert_name_handles_empty_input():
    assert cert_name(None) is None
    assert cert_name(()) is None


def test_days_remaining_computes_from_a_fixed_now():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert days_remaining("Jan 11 00:00:00 2026 GMT", now=now) == 10


def test_days_remaining_handles_a_malformed_string():
    assert days_remaining("not a date") is None


def test_days_remaining_handles_missing_input():
    assert days_remaining(None) is None


async def test_measure_tls_reports_an_error_result_for_a_closed_port_without_raising():
    port = _closed_port()
    result = await measure_tls("dead", "127.0.0.1", port=port, timeout=1.0)
    assert result.label == "dead"
    assert result.host == "127.0.0.1"
    assert result.error
    assert result.tls_handshake_ms is None
    assert result.ttfb_ms is None


async def test_tls_fanout_returns_a_result_per_target_all_with_errors():
    port = _closed_port()
    results = await tls_fanout(
        [("a", "127.0.0.1"), ("b", "127.0.0.1")],
        port=port,
        timeout=1.0,
        concurrency=2,
    )
    assert len(results) == 2
    assert all(r.error for r in results)
