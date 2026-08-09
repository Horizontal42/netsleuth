from __future__ import annotations

from netsleuth.probes.dns_leak import (
    build_adapter_result,
    build_dns_leak,
    detect_ecs_leak,
    parse_akahelp,
    parse_myaddr,
)


def test_akahelp_txt_records_become_a_flat_mapping():
    records = ['"ns" "203.0.113.9"', '"ecs" "198.51.100.0/24"', '"cip" "203.0.113.44"']
    assert parse_akahelp(records) == {
        "ns": "203.0.113.9",
        "ecs": "198.51.100.0/24",
        "cip": "203.0.113.44",
    }


def test_akahelp_records_without_quotes_are_handled_too():
    assert parse_akahelp(["ns 203.0.113.9"]) == {"ns": "203.0.113.9"}


def test_akahelp_ignores_records_it_cannot_split():
    assert parse_akahelp(["garbage", '"ns" "1.2.3.4"']) == {"ns": "1.2.3.4"}


def test_myaddr_returns_the_echoed_resolver_address():
    assert parse_myaddr(['"203.0.113.9"']) == "203.0.113.9"
    assert parse_myaddr(["203.0.113.9"]) == "203.0.113.9"


def test_myaddr_of_no_answer_is_none():
    assert parse_myaddr([]) is None
    assert parse_myaddr(['"not an ip"']) is None


def test_ecs_leak_is_detected_when_a_client_subnet_is_echoed():
    assert detect_ecs_leak({"ecs": "198.51.100.0/24"}) is True


def test_no_ecs_leak_when_the_field_is_absent_or_a_wildcard():
    assert detect_ecs_leak({}) is False
    assert detect_ecs_leak({"ecs": ""}) is False
    assert detect_ecs_leak({"ecs": "0.0.0.0/0"}) is False


def test_adapter_result_flags_a_resolver_in_a_different_asn():
    result = build_adapter_result(
        adapter="Wi-Fi",
        resolvers=["192.168.1.1"],
        echoed_ip="203.0.113.9",
        echoed_asn="AS64501",
        egress_asn="AS64500",
    )
    assert result.matches_egress_asn is False
    assert result.adapter == "Wi-Fi"
    assert result.configured_resolvers == ["192.168.1.1"]


def test_adapter_result_is_clean_when_the_asns_agree():
    result = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    assert result.matches_egress_asn is True


def test_adapter_result_is_unknown_when_either_asn_is_missing():
    assert build_adapter_result("eth0", ["1.1.1.1"], "1.1.1.1", None, "AS64500").matches_egress_asn is None
    assert build_adapter_result("eth0", ["1.1.1.1"], "1.1.1.1", "AS13335", None).matches_egress_asn is None


def test_adapter_result_asn_comparison_is_case_insensitive():
    assert build_adapter_result("eth0", ["1.1.1.1"], "1.1.1.1", "as64500", "AS64500").matches_egress_asn is True


def test_dns_leak_note_names_the_leaking_adapter():
    leaking = build_adapter_result("Wi-Fi", ["192.168.1.1"], "203.0.113.9", "AS64501", "AS64500")
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean, leaking], ecs_leaked=False)
    assert leak.ecs_leaked is False
    assert "Wi-Fi" in leak.note
    assert "browser" in leak.note.lower()


def test_dns_leak_note_is_clean_when_every_adapter_agrees():
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean], ecs_leaked=False)
    assert "no adapter" in leak.note.lower()


def test_dns_leak_note_mentions_ecs_when_the_subnet_leaked():
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean], ecs_leaked=True)
    assert leak.ecs_leaked is True
    assert "client subnet" in leak.note.lower()


_CYRILLIC = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")


def has_cyrillic(text: str) -> bool:
    return any(ch in _CYRILLIC for ch in text.lower())


def test_dns_leak_note_ru_names_the_leaking_adapter():
    leaking = build_adapter_result("Wi-Fi", ["192.168.1.1"], "203.0.113.9", "AS64501", "AS64500")
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean, leaking], ecs_leaked=False)
    assert leak.note_ru
    assert has_cyrillic(leak.note_ru)
    assert "Wi-Fi" in leak.note_ru


def test_dns_leak_note_ru_is_clean_when_every_adapter_agrees():
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean], ecs_leaked=False)
    assert leak.note_ru
    assert has_cyrillic(leak.note_ru)


def test_dns_leak_note_ru_mentions_ecs_when_the_subnet_leaked():
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean], ecs_leaked=True)
    assert leak.note_ru
    assert has_cyrillic(leak.note_ru)
