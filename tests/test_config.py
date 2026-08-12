from __future__ import annotations

import textwrap

import pytest
from pydantic import ValidationError

from netsleuth.config import load_settings

L7_YAML = textwrap.dedent(
    """
    tls:
      port: 8443
      concurrency: 2
    prefix_bench:
      max_prefixes: 8
    dpi_check:
      delay_between_ports_seconds: 0.5
    dns_advanced:
      bogus_resolver_ip: "198.51.100.1"
    path_diversity:
      max_targets: 5
    thresholds:
      tls_handshake_ms: { good: 50.0, warn: 150.0 }
    """
).strip()


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
    assert s.output.formats == ["md", "ru-md", "json", "prom", "csv"]


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


def test_l7_sections_default_without_any_yaml(tmp_path):
    s = load_settings(config_path=tmp_path / "nope.yaml", env_file=tmp_path / "nope.env")
    assert s.tls.port == 443
    assert s.tls.targets
    assert s.prefix_bench.max_prefixes == 32
    assert s.dpi_check.ports == [80, 443, 8443, 2083, 2096, 53]
    assert s.dns_advanced.doh_endpoints
    assert s.path_diversity.targets
    assert s.thresholds.tls_handshake_ms.warn == 300.0
    assert s.thresholds.tls_cpu_bound_ratio == 2.0


def test_l7_sections_yaml_overrides(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(L7_YAML, encoding="utf-8")
    s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
    assert s.tls.port == 8443
    assert s.tls.concurrency == 2
    assert s.prefix_bench.max_prefixes == 8
    assert s.dpi_check.delay_between_ports_seconds == 0.5
    assert s.dns_advanced.bogus_resolver_ip == "198.51.100.1"
    assert s.path_diversity.max_targets == 5
    assert s.thresholds.tls_handshake_ms.good == 50.0


def test_env_overrides_an_l7_section_field(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSLEUTH_PREFIX_BENCH__MAX_PREFIXES", "16")
    s = load_settings(config_path=tmp_path / "nope.yaml", env_file=tmp_path / "nope.env")
    assert s.prefix_bench.max_prefixes == 16


def test_dpi_check_ports_are_capped_so_it_cannot_become_a_range_scanner(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "dpi_check:\n  ports: [" + ", ".join(str(80 + i) for i in range(17)) + "]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="at most 16 ports"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_dpi_check_concurrency_is_capped_as_a_rate_limit(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("dpi_check:\n  concurrency: 10\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="concurrency"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_tls_pinned_fingerprints_accepts_valid_hex_and_normalizes_case_and_colons(tmp_path):
    path = tmp_path / "config.yaml"
    fingerprint_with_colons = ":".join(["AB"] * 32)
    path.write_text(
        f'tls:\n  pinned_fingerprints: {{"example.com": "{fingerprint_with_colons}"}}\n',
        encoding="utf-8",
    )
    s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
    assert s.tls.pinned_fingerprints["example.com"] == "ab" * 32


def test_tls_pinned_fingerprints_rejects_a_short_value(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('tls:\n  pinned_fingerprints: {"example.com": "aabbcc"}\n', encoding="utf-8")
    with pytest.raises(ValidationError, match="64-character hex"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_tls_pinned_fingerprints_rejects_non_hex_characters(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('tls:\n  pinned_fingerprints: {"example.com": "' + "zz" * 32 + '"}\n', encoding="utf-8")
    with pytest.raises(ValidationError, match="64-character hex"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_tls_pinned_fingerprints_are_capped_at_32_entries(tmp_path):
    path = tmp_path / "config.yaml"
    entries = ", ".join(f'"host{i}.example.com": "{"aa" * 32}"' for i in range(33))
    path.write_text("tls:\n  pinned_fingerprints: {" + entries + "}\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="at most 32"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_watch_webhook_min_interval_rejects_below_the_floor(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("watch:\n  webhook_min_interval_seconds: 29\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="below 30"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_watch_webhook_min_interval_accepts_the_floor(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("watch:\n  webhook_min_interval_seconds: 30\n", encoding="utf-8")
    s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
    assert s.watch.webhook_min_interval_seconds == 30


def test_watch_webhook_url_rejects_a_bad_scheme(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('watch:\n  webhook_url: "ftp://example.com/hook"\n', encoding="utf-8")
    with pytest.raises(ValidationError, match="http"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_watch_webhook_on_rejects_an_unknown_entry(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('watch:\n  webhook_on: ["crit", "banana"]\n', encoding="utf-8")
    with pytest.raises(ValidationError, match="banana"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_probing_ipv6_rejects_an_unknown_value(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('probing:\n  ipv6: "sometimes"\n', encoding="utf-8")
    with pytest.raises(ValidationError, match=r"auto.*off.*on"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_probing_ipv6_accepts_each_known_value(tmp_path):
    for value in ("auto", "on", "off"):
        path = tmp_path / "config.yaml"
        path.write_text(f'probing:\n  ipv6: "{value}"\n', encoding="utf-8")
        s = load_settings(config_path=path, env_file=tmp_path / "nope.env")
        assert s.probing.ipv6 == value


def test_ecmp_runs_are_capped(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("ecmp:\n  runs: 10\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="not exceed 5"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_ecmp_max_targets_are_capped(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("ecmp:\n  max_targets: 10\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="not exceed 3"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_history_trend_default_reports_is_capped(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("history:\n  trend_default_reports: 500\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="200"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_captive_portal_check_urls_are_capped(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "captive_portal:\n  check_urls: "
        + str([f"http://example{i}.com/generate_204" for i in range(5)])
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="at most 4"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")


def test_prefix_bench_max_prefixes_is_capped_so_it_cannot_scan_a_whole_as(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("prefix_bench:\n  max_prefixes: 1000\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="256"):
        load_settings(config_path=path, env_file=tmp_path / "nope.env")
