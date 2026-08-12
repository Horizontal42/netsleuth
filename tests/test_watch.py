from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsleuth.models import PingResult, SpeedResult
from netsleuth.watch import (
    WATCH_SCHEMA_VERSION,
    WatchSession,
    is_speedtest_cycle,
    next_delay,
    summarize_cycle,
    write_session,
)


def ping(label: str, avg: float | None, loss: float = 0.0) -> PingResult:
    return PingResult(
        label=label,
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_win",
        sent=5,
        received=5 if avg is not None else 0,
        loss_pct=loss,
        avg_ms=avg,
        jitter_ms=1.5,
    )


def test_the_first_cycle_measures_speed_so_the_session_has_a_baseline():
    assert is_speedtest_cycle(1, every_n=10) is True


def test_speed_is_measured_once_every_n_cycles():
    assert [c for c in range(1, 25) if is_speedtest_cycle(c, every_n=10)] == [1, 11, 21]


def test_an_interval_of_one_measures_speed_every_cycle():
    assert all(is_speedtest_cycle(c, every_n=1) for c in range(1, 6))


def test_a_non_positive_interval_disables_the_speedtest_entirely():
    assert [c for c in range(1, 10) if is_speedtest_cycle(c, every_n=0)] == []
    assert is_speedtest_cycle(3, every_n=-5) is False


def test_cycle_numbers_below_one_are_never_speedtest_cycles():
    assert is_speedtest_cycle(0, every_n=10) is False


def test_next_delay_subtracts_the_time_the_cycle_already_took():
    assert next_delay(cycle_started=100.0, now=104.0, interval=60.0) == pytest.approx(56.0)


def test_a_cycle_that_overran_its_interval_does_not_sleep_negatively():
    assert next_delay(cycle_started=100.0, now=400.0, interval=60.0) == 0.0


def test_summarize_cycle_flattens_the_hosts_and_omits_speed_when_it_did_not_run():
    summary = summarize_cycle(3, "2026-08-08T19:15:00Z", [ping("cloudflare-dns", 12.4)], None)
    assert summary["cycle"] == 3
    assert summary["at"] == "2026-08-08T19:15:00Z"
    assert summary["hosts"]["cloudflare-dns"]["avg_ms"] == 12.4
    assert summary["hosts"]["cloudflare-dns"]["loss_pct"] == 0.0
    assert summary["speed"] is None


def test_summarize_cycle_keeps_the_speed_figures_when_it_did_run():
    speed = SpeedResult(method="cloudflare", download_mbps=284.3, upload_mbps=41.7, bufferbloat_grade="B")
    summary = summarize_cycle(1, "2026-08-08T19:12:00Z", [ping("cloudflare-dns", 12.4)], speed)
    assert summary["speed"]["download_mbps"] == 284.3
    assert summary["speed"]["bufferbloat_grade"] == "B"


def test_summarize_cycle_records_a_dead_host_without_inventing_a_number():
    summary = summarize_cycle(2, "2026-08-08T19:13:00Z", [ping("google-dns", None, loss=100.0)], None)
    assert summary["hosts"]["google-dns"]["avg_ms"] is None
    assert summary["hosts"]["google-dns"]["loss_pct"] == 100.0


def test_summarize_cycle_reports_ok_verdict_for_a_healthy_tick():
    summary = summarize_cycle(1, "2026-08-08T19:12:00Z", [ping("cloudflare-dns", 12.4)], None)
    assert summary["status"] == "ok"
    assert summary["score"] == 100
    assert summary["finding_ids"] == []


def test_summarize_cycle_reports_a_degraded_verdict_with_finding_ids():
    summary = summarize_cycle(1, "2026-08-08T19:12:00Z", [ping("cloudflare-dns", None, loss=100.0)], None)
    assert summary["status"] == "crit"
    assert summary["score"] < 100
    assert any(fid.startswith("latency.unreachable") for fid in summary["finding_ids"])


def test_summarize_cycle_verdict_considers_a_bad_speed_cycle_too():
    speed = SpeedResult(method="cloudflare", download_mbps=100.0, upload_mbps=20.0, bufferbloat_down_ms=250.0)
    summary = summarize_cycle(1, "2026-08-08T19:12:00Z", [ping("cloudflare-dns", 12.4)], speed)
    assert summary["status"] in ("warn", "crit")
    assert any(fid.startswith("speed.bufferbloat") for fid in summary["finding_ids"])


def test_session_history_returns_the_series_for_one_host_with_gaps_preserved():
    session = WatchSession(started_at="2026-08-08T19:12:00Z", asn="AS64500")
    session.add(summarize_cycle(1, "t1", [ping("cloudflare-dns", 12.0)], None))
    session.add(summarize_cycle(2, "t2", [ping("cloudflare-dns", None, loss=100.0)], None))
    session.add(summarize_cycle(3, "t3", [ping("cloudflare-dns", 14.0)], None))
    assert session.history("cloudflare-dns") == [12.0, None, 14.0]
    assert session.history("absent-host") == [None, None, None]


def test_session_filename_marks_it_as_a_watch_artifact():
    session = WatchSession(started_at="2026-08-08T19:12:00Z", asn="AS64500")
    assert session.filename() == "watch_AS64500_20260808T191200Z.json"
    assert WatchSession(started_at="2026-08-08T19:12:00Z").filename().startswith("watch_unknown_")


def test_a_session_writes_exactly_one_artifact_holding_every_cycle(tmp_path: Path):
    session = WatchSession(
        started_at="2026-08-08T19:12:00Z", asn="AS64500", interval_seconds=60, speedtest_every_n_cycles=10
    )
    for cycle in range(1, 4):
        session.add(summarize_cycle(cycle, f"t{cycle}", [ping("cloudflare-dns", 12.0 + cycle)], None))
    path = write_session(session, tmp_path)
    assert list(tmp_path.iterdir()) == [path]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == WATCH_SCHEMA_VERSION
    assert payload["kind"] == "watch"
    assert payload["meta"]["interval_seconds"] == 60
    assert payload["meta"]["speedtest_every_n_cycles"] == 10
    assert [c["cycle"] for c in payload["cycles"]] == [1, 2, 3]


def test_an_empty_session_still_writes_a_well_formed_artifact(tmp_path: Path):
    path = write_session(WatchSession(started_at="2026-08-08T19:12:00Z"), tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["cycles"] == []
    assert payload["meta"]["finished_at"]
