from __future__ import annotations

import pytest

from netsleuth.reputation import decode_dnsbl, reverse_ip, summarize_dnsbl


def test_reverse_ip_builds_the_dnsbl_query_label():
    assert reverse_ip("203.0.113.44") == "44.113.0.203"
    assert reverse_ip("8.8.8.8") == "8.8.8.8"


def test_reverse_ip_rejects_ipv6_because_classic_dnsbls_are_v4_only():
    with pytest.raises(ValueError):
        reverse_ip("2001:db8::1")


def test_a_real_spamhaus_listing_is_reported_as_listed():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.0.0.2", "127.0.0.4"])
    assert outcome.listed is True
    assert outcome.unavailable_reason is None
    assert outcome.codes == ["127.0.0.2", "127.0.0.4"]


def test_public_resolver_error_code_is_not_a_listing():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.255.255.254"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "query_via_public_resolver"
    assert outcome.codes == ["127.255.255.254"]


def test_rate_limit_error_code_is_not_a_listing():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.255.255.255"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "rate_limited"


@pytest.mark.parametrize(
    "code",
    ["127.255.255.252", "127.255.255.253", "127.255.255.0", "127.255.255.1"],
)
def test_every_other_code_in_the_error_range_is_a_provider_error_not_a_listing(code):
    outcome = decode_dnsbl("zen.spamhaus.org", [code])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "provider_error"


def test_an_error_code_mixed_with_a_listing_code_still_means_unavailable():
    # A response carrying an error code cannot be trusted for the listing bits.
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.0.0.2", "127.255.255.254"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "query_via_public_resolver"


def test_no_answers_means_not_listed_and_no_error():
    outcome = decode_dnsbl("bl.spamcop.net", [])
    assert outcome.listed is False
    assert outcome.unavailable_reason is None
    assert outcome.codes == []


def test_a_non_loopback_answer_is_ignored_as_a_listing():
    outcome = decode_dnsbl("dnsbl.dronebl.org", ["10.0.0.1"])
    assert outcome.listed is False
    assert outcome.unavailable_reason is None


def test_summarize_returns_only_real_listings():
    outcomes = [
        decode_dnsbl("zen.spamhaus.org", ["127.255.255.254"]),
        decode_dnsbl("bl.spamcop.net", ["127.0.0.2"]),
        decode_dnsbl("b.barracudacentral.org", []),
    ]
    hits, blocked = summarize_dnsbl(outcomes)
    assert [h.zone for h in hits] == ["bl.spamcop.net"]
    assert hits[0].codes == ["127.0.0.2"]
    assert blocked is True


def test_summarize_reports_not_blocked_when_every_zone_answered_cleanly():
    outcomes = [
        decode_dnsbl("zen.spamhaus.org", []),
        decode_dnsbl("bl.spamcop.net", []),
    ]
    hits, blocked = summarize_dnsbl(outcomes)
    assert hits == []
    assert blocked is False

def test_fallback_provider_error_with_unknown_error_code():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.255.255.999"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "provider_error"

def test_mixed_listing_and_normal_codes():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.0.0.2", "192.168.1.1"])
    assert outcome.listed is True
    assert outcome.unavailable_reason is None
