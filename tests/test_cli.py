import os
from pathlib import Path, PurePosixPath
from unittest.mock import MagicMock, patch

from netsleuth.cli import _dedupe, _os_timezone, parse_target
from netsleuth.models import Finding


def test_parse_target_asn():
    assert parse_target("AS12345") == ("asn", "AS12345")
    assert parse_target("as12345") == ("asn", "AS12345")
    assert parse_target("12345") == ("asn", "AS12345")
    assert parse_target("  AS12345  ") == ("asn", "AS12345")


def test_parse_target_ip():
    assert parse_target("1.2.3.4") == ("ip", "1.2.3.4")
    assert parse_target("2001:db8::1") == ("ip", "2001:db8::1")
    assert parse_target("  1.2.3.4  ") == ("ip", "1.2.3.4")


def test_parse_target_domain():
    assert parse_target("example.com") == ("domain", "example.com")
    assert parse_target("foo-bar.baz") == ("domain", "foo-bar.baz")
    assert parse_target("  example.com  ") == ("domain", "example.com")


def test_dedupe_empty():
    assert _dedupe([]) == []


def test_dedupe_unique():
    findings = [
        Finding(id="f1", severity="info", title="1", detail="1"),
        Finding(id="f2", severity="info", title="2", detail="2"),
        Finding(id="f3", severity="info", title="3", detail="3"),
    ]
    assert _dedupe(findings) == findings


def test_dedupe_duplicates():
    f1 = Finding(id="f1", severity="info", title="1", detail="1")
    f2 = Finding(id="f2", severity="info", title="2", detail="2")
    f1_dup = Finding(id="f1", severity="warn", title="dup", detail="dup")
    findings = [f1, f2, f1_dup, f1, f2]
    deduped = _dedupe(findings)
    assert len(deduped) == 2
    assert deduped[0] is f1
    assert deduped[1] is f2


def test_os_timezone_from_env(monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")
    assert _os_timezone() == "America/New_York"


@patch("netsleuth.cli.Path")
def test_os_timezone_from_localtime_symlink(mock_path, monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    mock_localtime = MagicMock()
    mock_localtime.is_symlink.return_value = True
    mock_localtime.readlink.return_value = PurePosixPath("/usr/share/zoneinfo/Europe/London")

    def side_effect(path, *args, **kwargs):
        if str(path) == "/etc/localtime":
            return mock_localtime
        return MagicMock()

    mock_path.side_effect = side_effect
    assert _os_timezone() == "Europe/London"


@patch("netsleuth.cli.Path")
def test_os_timezone_from_timezone_file(mock_path, monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    mock_localtime = MagicMock()
    mock_localtime.is_symlink.return_value = False

    mock_timezone = MagicMock()
    mock_timezone.read_text.return_value = "Asia/Tokyo\n"

    def side_effect(path, *args, **kwargs):
        if str(path) == "/etc/localtime":
            return mock_localtime
        if str(path) == "/etc/timezone":
            return mock_timezone
        return MagicMock()

    mock_path.side_effect = side_effect
    assert _os_timezone() == "Asia/Tokyo"


@patch("netsleuth.cli.Path")
def test_os_timezone_none(mock_path, monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    mock_localtime = MagicMock()
    mock_localtime.is_symlink.return_value = False

    mock_timezone = MagicMock()
    mock_timezone.read_text.side_effect = OSError("File not found")

    def side_effect(path, *args, **kwargs):
        if str(path) == "/etc/localtime":
            return mock_localtime
        if str(path) == "/etc/timezone":
            return mock_timezone
        return MagicMock()

    mock_path.side_effect = side_effect
    assert _os_timezone() is None
