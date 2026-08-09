from __future__ import annotations

import textwrap

import pytest
from pydantic import ValidationError

from netsleuth.config import load_settings


@pytest.fixture()
def yaml_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        textwrap.dedent(
            """
            timeouts:
              http_seconds: 3.5
            probing:
              ping_count: 7
              reference_hosts:
                - { label: "yaml-host", host: "9.9.9.9" }
            output:
              logs_dir: "./yaml-logs"
              emoji: false
            thresholds:
              latency_ms: { good: 11.0, warn: 22.0 }
            """
        ).strip(),
        encoding="utf-8",
    )
    return path


def test_defaults_apply_when_yaml_omits_a_field(yaml_file, tmp_path):
    s = load_settings(config_path=yaml_file, env_file=tmp_path / "missing.env")
    assert s.probing.max_hops == 30
    assert s.timeouts.module_seconds == 30.0


def test_yaml_overrides_defaults(yaml_file, tmp_path):
    s = load_settings(config_path=yaml_file, env_file=tmp_path / "missing.env")
    assert s.timeouts.http_seconds == 3.5
    assert s.probing.ping_count == 7
    assert s.output.emoji is False
    assert s.thresholds.latency_ms.warn == 22.0
    assert s.probing.reference_hosts[0].host == "9.9.9.9"


def test_dotenv_overrides_yaml(yaml_file, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("NETSLEUTH_PROBING__PING_COUNT=13\n", encoding="utf-8")
    s = load_settings(config_path=yaml_file, env_file=env_file)
    assert s.probing.ping_count == 13


def test_environment_overrides_dotenv(yaml_file, tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NETSLEUTH_PROBING__PING_COUNT=13\n", encoding="utf-8")
    monkeypatch.setenv("NETSLEUTH_PROBING__PING_COUNT", "99")
    s = load_settings(config_path=yaml_file, env_file=env_file)
    assert s.probing.ping_count == 99


def test_secrets_default_to_none_so_the_tool_runs_unconfigured(tmp_path):
    s = load_settings(config_path=tmp_path / "absent.yaml", env_file=tmp_path / "absent.env")
    assert s.ipinfo_token is None
    assert s.peeringdb_api_key is None
    assert s.abuseipdb_api_key is None


def test_secrets_load_from_dotenv_without_the_nested_prefix(tmp_path, monkeypatch):
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("IPINFO_TOKEN=abc123\n", encoding="utf-8")
    s = load_settings(config_path=tmp_path / "absent.yaml", env_file=env_file)
    assert s.ipinfo_token is not None
    assert s.ipinfo_token.get_secret_value() == "abc123"
    assert "abc123" not in repr(s)


def test_missing_yaml_is_not_an_error(tmp_path):
    s = load_settings(config_path=tmp_path / "nope.yaml", env_file=tmp_path / "nope.env")
    assert s.probing.ping_count == 20


def test_output_formats_defaults_to_english_markdown_only(tmp_path):
    s = load_settings(config_path=tmp_path / "nope.yaml", env_file=tmp_path / "nope.env")
    assert s.output.formats == ["md"]


def test_output_formats_yaml_override(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        textwrap.dedent(
            """
            output:
              formats: ["md", "json"]
            """
        ).strip(),
        encoding="utf-8",
    )
    s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
    assert s.output.formats == ["md", "json"]


def test_output_formats_all_expands_to_every_known_format(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('output:\n  formats: ["all"]\n', encoding="utf-8")
    s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
    assert s.output.formats == ["md", "ru-md", "json"]


def test_output_formats_dedupes_and_lowercases(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('output:\n  formats: ["MD", "md", "JSON"]\n', encoding="utf-8")
    s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
    assert s.output.formats == ["md", "json"]


def test_output_formats_rejects_unknown_value(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('output:\n  formats: ["pdf"]\n', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")
