import os
from unittest.mock import MagicMock, patch

from netsleuth.cli import _os_timezone


def test_os_timezone_tz_env():
    with patch.dict(os.environ, {"TZ": "Europe/Berlin"}):
        assert _os_timezone() == "Europe/Berlin"

def test_os_timezone_localtime_symlink():
    with patch.dict(os.environ, {}, clear=True):
        with patch("netsleuth.cli.Path") as MockPath:
            mock_localtime = MagicMock()
            mock_localtime.is_symlink.return_value = True
            mock_localtime.readlink.return_value = "/usr/share/zoneinfo/America/New_York"

            # Make Path("/etc/localtime") return mock_localtime
            MockPath.return_value = mock_localtime

            assert _os_timezone() == "America/New_York"
            MockPath.assert_called_once_with("/etc/localtime")

def test_os_timezone_timezone_file():
    with patch.dict(os.environ, {}, clear=True):
        with patch("netsleuth.cli.Path") as MockPath:
            mock_localtime = MagicMock()
            mock_localtime.is_symlink.return_value = False

            mock_timezone = MagicMock()
            mock_timezone.read_text.return_value = "Asia/Tokyo\n"

            def side_effect(path):
                if path == "/etc/localtime":
                    return mock_localtime
                elif path == "/etc/timezone":
                    return mock_timezone
                return MagicMock()

            MockPath.side_effect = side_effect

            assert _os_timezone() == "Asia/Tokyo"

def test_os_timezone_oserror():
    with patch.dict(os.environ, {}, clear=True):
        with patch("netsleuth.cli.Path") as MockPath:
            mock_localtime = MagicMock()
            mock_localtime.is_symlink.return_value = False

            mock_timezone = MagicMock()
            mock_timezone.read_text.side_effect = OSError("Permission denied")

            def side_effect(path):
                if path == "/etc/localtime":
                    return mock_localtime
                elif path == "/etc/timezone":
                    return mock_timezone
                return MagicMock()

            MockPath.side_effect = side_effect

            assert _os_timezone() is None
