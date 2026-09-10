from __future__ import annotations

import httpx

from netsleuth.alerting import build_payload, post_webhook, should_fire
from netsleuth.config import Watch
from netsleuth.exporter import dump_json


def test_should_fire_is_silent_on_the_first_ever_tick():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire(None, "crit", None, 100.0, watch) is False


def test_should_fire_is_silent_when_there_is_no_transition():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire("crit", "crit", None, 100.0, watch) is False


def test_should_fire_is_silent_when_the_new_state_is_not_in_fire_on():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire("ok", "warn", None, 100.0, watch) is False


def test_should_fire_respects_the_minimum_interval():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire("ok", "crit", 100.0, 150.0, watch) is False


def test_should_fire_fires_after_the_interval_elapses():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire("ok", "crit", 100.0, 450.0, watch) is True


def test_should_fire_fires_on_first_transition_with_no_prior_firing():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire("ok", "crit", None, 100.0, watch) is True


def test_should_fire_treats_recovery_as_a_separate_event():
    watch1 = Watch(webhook_min_interval_seconds=300, webhook_on=["crit"])
    assert should_fire("crit", "ok", None, 100.0, watch1) is False
    watch2 = Watch(webhook_min_interval_seconds=300, webhook_on=["crit", "recovered"])
    assert should_fire("crit", "ok", None, 100.0, watch2) is True


def test_should_fire_does_not_treat_info_to_ok_as_a_recovery():
    watch = Watch(webhook_min_interval_seconds=300, webhook_on=["recovered"])
    assert should_fire("info", "ok", None, 100.0, watch) is False


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
        ok = await post_webhook(
            client, "https://example.com/hook", {"a": 1}, timeout=5.0
        )
    assert ok is True


async def test_post_webhook_returns_false_and_never_raises_on_failure(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=500)
    async with httpx.AsyncClient() as client:
        ok = await post_webhook(
            client, "https://example.com/hook", {"a": 1}, timeout=5.0
        )
    assert ok is False
