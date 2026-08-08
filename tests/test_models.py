from __future__ import annotations

import json

import pytest

from netcheck.models import Finding, ModuleResult, ProbeError, Signal, to_jsonable


def test_probe_error_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown ProbeError kind"):
        ProbeError(source="ip-api", kind="exploded", message="boom")


@pytest.mark.parametrize(
    "kind",
    [
        "timeout",
        "http_error",
        "rate_limited",
        "blocked",
        "parse_error",
        "unavailable",
        "no_privilege",
        "not_applicable",
    ],
)
def test_probe_error_accepts_documented_kinds(kind):
    assert ProbeError(source="s", kind=kind, message="m").kind == kind


def test_module_result_rejects_unknown_status():
    with pytest.raises(ValueError, match="unknown ModuleResult status"):
        ModuleResult(name="bgp", status="borked")


def test_module_result_serializes_to_strict_json():
    result = ModuleResult(
        name="reputation",
        status="partial",
        data={"firehol_hits": ["firehol_level1"]},
        errors=[ProbeError(source="internetdb", kind="timeout", message="8s", retryable=True)],
        warnings=["abuseipdb key missing"],
        started_at="2026-08-08T19:12:00Z",
        duration_ms=1234,
    )
    text = json.dumps(to_jsonable(result), allow_nan=False)
    back = json.loads(text)
    assert back["name"] == "reputation"
    assert back["status"] == "partial"
    assert back["data"]["firehol_hits"] == ["firehol_level1"]
    assert back["errors"][0] == {
        "source": "internetdb",
        "kind": "timeout",
        "message": "8s",
        "retryable": True,
    }
    assert back["warnings"] == ["abuseipdb key missing"]
    assert back["duration_ms"] == 1234


def test_to_jsonable_coerces_non_finite_numbers_to_null():
    payload = {"a": float("inf"), "b": float("-inf"), "c": float("nan"), "d": 1.5}
    out = to_jsonable(payload)
    assert out == {"a": None, "b": None, "c": None, "d": 1.5}
    json.dumps(out, allow_nan=False)


def test_to_jsonable_handles_nested_dataclasses_and_sets():
    finding = Finding(
        id="latency.high",
        severity="warn",
        title="Latency above target",
        detail="avg 130 ms to 1.1.1.1",
        metric="avg_ms",
        value=130.0,
        threshold=100.0,
        advice="Check for a saturated uplink.",
    )
    signal = Signal(name="tunnel_iface", observed=True, weight=0.35, direction="vpn", note="wg0")
    out = to_jsonable({"findings": [finding], "signals": (signal,), "tags": {"a"}})
    assert out["findings"][0]["severity"] == "warn"
    assert out["signals"][0]["weight"] == 0.35
    assert out["tags"] == ["a"]
    json.dumps(out, allow_nan=False)


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError, match="unknown Finding severity"):
        Finding(
            id="x",
            severity="apocalyptic",
            title="t",
            detail="d",
            metric=None,
            value=None,
            threshold=None,
            advice=None,
        )
