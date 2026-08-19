from __future__ import annotations

from netsleuth.interpret import pmtud_findings
from netsleuth.models import PmtuResult
from netsleuth.probes.pmtud import (
    classify_pmtu,
    mtu_from_search,
    next_probe_size,
    unix_ping_df_argv,
)


def test_next_probe_size_bisects():
    assert next_probe_size(576, 1500) == 1038


def test_next_probe_size_converges_over_repeated_bisection():
    low, high = 576, 1500
    for _ in range(20):
        if high - low <= 1:
            break
        mid = next_probe_size(low, high)
        assert low < mid < high
        low = mid  # simulate "always succeeds" to force convergence toward high
    assert high - low <= 1


def test_next_probe_size_off_by_one_at_the_lower_bound():
    assert next_probe_size(576, 577) == 576


def test_next_probe_size_off_by_one_at_the_upper_bound():
    assert next_probe_size(1499, 1500) == 1499


def test_next_probe_size_handles_a_reversed_range_without_raising():
    # low > high should never happen in the real search loop, but must not crash.
    assert isinstance(next_probe_size(1500, 576), int)


def test_mtu_from_search_adds_the_overhead():
    assert mtu_from_search(1472, 1473, overhead=28) == 1500


def test_mtu_from_search_default_overhead():
    assert mtu_from_search(1472, 1473) == 1500


def test_classify_pmtu_ok_when_discovered_meets_the_floor():
    verdict, note, note_ru = classify_pmtu(1500, None, False)
    assert verdict == "ok"
    assert note and note_ru


def test_classify_pmtu_reduced_when_frag_needed_was_seen():
    verdict, note, note_ru = classify_pmtu(1400, None, True)
    assert verdict == "reduced"
    assert "1400" in note


def test_classify_pmtu_blackhole_when_no_frag_needed_signal():
    verdict, note, note_ru = classify_pmtu(1400, None, False)
    assert verdict == "blackhole"


def test_classify_pmtu_unknown_when_discovered_is_none():
    verdict, note, note_ru = classify_pmtu(None, None, False)
    assert verdict == "unknown"


def test_classify_pmtu_uses_iface_mtu_as_the_floor_when_smaller_than_standard():
    verdict, _note, _note_ru = classify_pmtu(1400, 1400, False)
    assert verdict == "ok"


def test_unix_ping_df_argv_linux():
    argv = unix_ping_df_argv("/bin/ping", "example.com", 1472, 2.0, "Linux")
    assert argv == ["/bin/ping", "-M", "do", "-s", "1472", "-c", "1", "-W", "2", "example.com"]


def test_unix_ping_df_argv_darwin():
    argv = unix_ping_df_argv("/sbin/ping", "example.com", 1472, 2.0, "Darwin")
    assert argv == ["/sbin/ping", "-D", "-s", "1472", "-c", "1", "-t", "2", "example.com"]


def test_unix_ping_df_argv_rounds_a_fractional_timeout_up():
    argv = unix_ping_df_argv("/bin/ping", "example.com", 1472, 1.2, "Linux")
    assert "-W" in argv
    assert argv[argv.index("-W") + 1] == "2"


def pmtu(**kw) -> PmtuResult:
    base = dict(host="example.com", resolved_ip="1.2.3.4", method="icmp_win", verdict="unknown")
    base.update(kw)
    return PmtuResult(**base)


def test_pmtud_findings_silent_when_unknown():
    assert pmtud_findings(pmtu(verdict="unknown")) == []


def test_pmtud_findings_crit_on_blackhole():
    findings = pmtud_findings(pmtu(verdict="blackhole", discovered_mtu=1400, note="x", note_ru="y"))
    assert [f.id for f in findings] == ["path.pmtu_blackhole.example.com"]
    assert findings[0].severity == "crit"


def test_pmtud_findings_on_reduced_mtu():
    findings = pmtud_findings(pmtu(verdict="reduced", discovered_mtu=1400, note="x", note_ru="y"))
    ids = [f.id for f in findings]
    assert "path.pmtu_reduced.example.com" in ids


def test_pmtud_findings_also_flags_when_below_local_iface_mtu():
    findings = pmtud_findings(
        pmtu(verdict="reduced", discovered_mtu=1400, iface_mtu=1500, note="x", note_ru="y")
    )
    ids = [f.id for f in findings]
    assert "path.pmtu_below_iface_mtu.example.com" in ids


def test_pmtud_findings_silent_on_ok_verdict():
    assert pmtud_findings(pmtu(verdict="ok", discovered_mtu=1500)) == []
