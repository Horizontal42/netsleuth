from __future__ import annotations

import pytest
import typer

from netsleuth.cli import format_siblings, parse_formats

DEFAULT = frozenset({"md"})


def test_no_flags_returns_the_default():
    assert parse_formats([], ru=False, json_flag=False, default=DEFAULT) == DEFAULT


def test_json_shortcut_selects_json_only():
    assert parse_formats([], ru=False, json_flag=True, default=DEFAULT) == frozenset({"json"})


def test_ru_shortcut_selects_ru_md_only():
    assert parse_formats([], ru=True, json_flag=False, default=DEFAULT) == frozenset({"ru-md"})


def test_json_and_format_md_stack():
    assert parse_formats(["md"], ru=False, json_flag=True, default=DEFAULT) == frozenset({"md", "json"})


def test_repeated_format_flags_union():
    assert parse_formats(["md", "json"], ru=False, json_flag=False, default=DEFAULT) == frozenset(
        {"md", "json"}
    )


def test_comma_separated_single_flag():
    assert parse_formats(["md,json"], ru=False, json_flag=False, default=DEFAULT) == frozenset(
        {"md", "json"}
    )


def test_all_expands_to_every_known_format():
    assert parse_formats(["all"], ru=False, json_flag=False, default=DEFAULT) == frozenset(
        {"md", "ru-md", "json", "prom", "csv"}
    )


def test_none_alone_means_write_nothing():
    assert parse_formats(["none"], ru=False, json_flag=False, default=DEFAULT) == frozenset()


def test_none_combined_with_another_format_is_an_error():
    with pytest.raises(typer.BadParameter):
        parse_formats(["none,md"], ru=False, json_flag=False, default=DEFAULT)


def test_unknown_format_is_an_error():
    with pytest.raises(typer.BadParameter):
        parse_formats(["pdf"], ru=False, json_flag=False, default=DEFAULT)


def test_case_and_whitespace_are_normalized():
    assert parse_formats([" MD ", "JSON"], ru=False, json_flag=False, default=DEFAULT) == frozenset(
        {"md", "json"}
    )


def test_order_of_flags_never_changes_the_result():
    a = parse_formats(["json", "md"], ru=False, json_flag=False, default=DEFAULT)
    b = parse_formats(["md", "json"], ru=False, json_flag=False, default=DEFAULT)
    assert a == b


def test_format_siblings_cross_link_when_both_languages_selected():
    result = format_siblings(frozenset({"md", "ru-md"}), "report.md", "report.ru.md")
    assert result == ("report.ru.md", "report.md")


def test_format_siblings_are_none_when_only_english_selected():
    assert format_siblings(frozenset({"md"}), "report.md", "report.ru.md") == (None, None)


def test_format_siblings_are_none_when_only_russian_selected():
    assert format_siblings(frozenset({"ru-md"}), "report.md", "report.ru.md") == (None, None)


def test_format_siblings_are_none_when_neither_markdown_selected():
    assert format_siblings(frozenset({"json"}), "report.md", "report.ru.md") == (None, None)
