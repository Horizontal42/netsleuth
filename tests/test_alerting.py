from __future__ import annotations

import httpx
import pytest

from netsleuth.alerting import build_payload, post_webhook, should_fire
from netsleuth.exporter import dump_json


def test_should_fire_is_silent_on_the_first_ever_tick():
    assert should_fire(None, "crit", None, 100.0, 300.0, {"crit"}) is False


def test_should_fire_is_silent_when_there_is_no_transition():
    assert should_fire("crit", "crit", None, 100.0, 300.0, {"crit"}) is False


def test_should_fire_is_silent_when_the_new_state_is_not_in_fire_on():
    assert should_fire("ok", "warn", None, 100.0, 300.0, {"crit"}) is False


def test_should_fire_respects_the_minimum_interval():
    assert should_fire("ok", "crit", 100.0, 150.0, 300.0, {"crit"}) is False


def test_should_fire_fires_after_the_interval_elapses():
    assert should_fire("ok", "crit", 100.0, 450.0, 300.0, {"crit"}) is True


def test_should_fire_fires_on_first_transition_with_no_prior_firing():
    assert should_fire("ok", "crit", None, 100.0, 300.0, {"crit"}) is True


def test_should_fire_treats_recovery_as_a_separate_event():
    assert should_fire("crit", "ok", None, 100.0, 300.0, {"crit"}) is False
    assert should_fire("crit", "ok", None, 100.0, 300.0, {"crit", "recovered"}) is True


def test_should_fire_does_not_treat_info_to_ok_as_a_recovery():
    assert should_fire("info", "ok", None, 100.0, 300.0, {"recovered"}) is False


def test_build_payload_shape_and_json_serializable():
    payload = build_payload(
        {"asn": "AS64500", "interface": "Ethernet"},
        {"at": "2026-08-12T00:00:00Z", "score": 42, "finding_ids": ["latency.avg.a"]},
        "ok",
        "crit",
    )
    assert payload["tool"] == "netsleuth"
    assert payload["asn"] == "AS64500"
    assert payload["previous"] == "ok"
    assert payload["current"] == "crit"
    assert payload["score"] == 42
    assert payload["findings"] == ["latency.avg.a"]
    dump_json(payload)  # must not raise


async def test_post_webhook_returns_true_on_success(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=200)
    async with httpx.AsyncClient() as client:
        ok = await post_webhook(client, "https://example.com/hook", {"a": 1}, timeout=5.0)
    assert ok is True


async def test_post_webhook_returns_false_and_never_raises_on_failure(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=500)
    async with httpx.AsyncClient() as client:
        ok = await post_webhook(client, "https://example.com/hook", {"a": 1}, timeout=5.0)
    assert ok is False
