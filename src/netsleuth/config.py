from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, SecretStr, field_validator

FORMAT_EXTENSIONS = {"md": "md", "ru-md": "ru.md", "json": "json"}
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

DEFAULT_CONFIG_PATH = Path("config.yaml")
DEFAULT_ENV_PATH = Path(".env")


class Timeouts(BaseModel):
    http_seconds: float = 8.0
    module_seconds: float = 30.0
    speedtest_seconds: float = 90.0
    dns_seconds: float = 4.0
    subprocess_seconds: float = 60.0


class HostSpec(BaseModel):
    label: str
    host: str


class Probing(BaseModel):
    reference_hosts: list[HostSpec] = Field(
        default_factory=lambda: [
            HostSpec(label="cloudflare-dns", host="1.1.1.1"),
            HostSpec(label="google-dns", host="8.8.8.8"),
            HostSpec(label="quad9-dns", host="9.9.9.9"),
        ]
    )
    service_hosts: list[HostSpec] = Field(
        default_factory=lambda: [
            HostSpec(label="cloudflare", host="cloudflare.com"),
            HostSpec(label="google", host="google.com"),
            HostSpec(label="github", host="github.com"),
        ]
    )
    ping_count: int = 20
    quick_ping_count: int = 5
    ping_interval_seconds: float = 0.25
    ping_timeout_seconds: float = 2.0
    mtr_cycles: int = 10
    quick_mtr_cycles: int = 1
    max_hops: int = 30
    trace_concurrency: int = 2


class Speedtest(BaseModel):
    enabled_tiers: list[str] = Field(default_factory=lambda: ["ookla_bin", "cloudflare", "fastcom"])
    download_sizes_bytes: list[int] = Field(default_factory=lambda: [1_000_000, 10_000_000, 25_000_000])
    upload_sizes_bytes: list[int] = Field(default_factory=lambda: [1_000_000, 5_000_000])
    cloudflare_base_url: str = "https://speed.cloudflare.com"
    fastcom_api_url: str = "https://api.fast.com/netflix/speedtest/v2"
    ndt7_locate_url: str = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
    bufferbloat_probe_interval_seconds: float = 0.2


class Providers(BaseModel):
    cf_trace_url: str = "https://www.cloudflare.com/cdn-cgi/trace"
    ip_api_url: str = "http://ip-api.com/json/"
    freeipapi_url: str = "https://freeipapi.com/api/json/"
    ipinfo_url: str = "https://ipinfo.io/"
    ipwhois_url: str = "https://ipwho.is/"
    ripestat_base_url: str = "https://stat.ripe.net/data"
    asrank_url: str = "https://api.asrank.caida.org/v2/graphql"
    peeringdb_base_url: str = "https://www.peeringdb.com/api"
    internetdb_url: str = "https://internetdb.shodan.io/"
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    cymru_origin_zone: str = "origin.asn.cymru.com"
    cymru_asn_zone: str = "asn.cymru.com"
    ripestat_max_rows: int = 200
    ripestat_timeframe_days: int = 14
    peeringdb_cache_hours: int = 24
    firehol_refresh_hours: int = 24
    firehol_netsets: list[str] = Field(default_factory=list)


class Dnsbl(BaseModel):
    zones: list[str] = Field(
        default_factory=lambda: [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "b.barracudacentral.org",
            "dnsbl.dronebl.org",
        ]
    )


class Band(BaseModel):
    good: float
    warn: float


class BufferbloatBands(BaseModel):
    a: float = 5.0
    b: float = 30.0
    c: float = 60.0
    d: float = 200.0
    e: float = 400.0


class VpnBands(BaseModel):
    likely: float = 0.40
    confirmed: float = 0.75


class Thresholds(BaseModel):
    latency_ms: Band = Band(good=40.0, warn=100.0)
    jitter_ms: Band = Band(good=5.0, warn=20.0)
    loss_pct: Band = Band(good=0.0, warn=2.0)
    bufferbloat_ms: BufferbloatBands = BufferbloatBands()
    vpn_confidence: VpnBands = VpnBands()
    tls_handshake_ms: Band = Band(good=100.0, warn=300.0)
    ttfb_ms: Band = Band(good=200.0, warn=800.0)
    dns_resolve_ms: Band = Band(good=30.0, warn=120.0)
    prefix_spread_ms: Band = Band(good=20.0, warn=80.0)
    tls_cpu_bound_ratio: float = 2.0
    first_hop_ms: Band = Band(good=5.0, warn=25.0)


class TlsConfig(BaseModel):
    targets: list[HostSpec] = Field(
        default_factory=lambda: [
            HostSpec(label="cloudflare", host="cloudflare.com"),
            HostSpec(label="google", host="google.com"),
        ]
    )
    port: int = 443
    concurrency: int = 4
    ttfb_path: str = "/"


class PrefixBenchConfig(BaseModel):
    max_prefixes: int = 32
    ping_count: int = 3
    concurrency: int = 8
    host_offset: int = 1
    family: int = 4

    @field_validator("max_prefixes")
    @classmethod
    def _cap_max_prefixes(cls, value: int) -> int:
        if value > 256:
            raise ValueError(
                "prefix_bench.max_prefixes may not exceed 256 "
                "(this benchmarks a handful of your own AS's PoPs, not a mass scan of the whole AS)"
            )
        return value


class DpiCheckConfig(BaseModel):
    ports: list[int] = Field(default_factory=lambda: [80, 443, 8443, 2083, 2096, 53])
    connect_timeout_seconds: float = 3.0
    delay_between_ports_seconds: float = 0.25
    concurrency: int = 2

    @field_validator("ports")
    @classmethod
    def _cap_ports(cls, value: list[int]) -> list[int]:
        if len(value) > 16:
            raise ValueError(
                "dpi_check.ports may list at most 16 ports "
                "(this is a single-host self-diagnostic, not a port-range scanner)"
            )
        return value

    @field_validator("concurrency")
    @classmethod
    def _cap_concurrency(cls, value: int) -> int:
        if value > 4:
            raise ValueError("dpi_check.concurrency may not exceed 4 (keep the self-check rate-limited)")
        return value


class DohEndpoint(BaseModel):
    name: str
    url: str


class DnsAdvancedConfig(BaseModel):
    control_names: list[str] = Field(default_factory=lambda: ["cloudflare.com", "example.com"])
    doh_endpoints: list[DohEndpoint] = Field(
        default_factory=lambda: [
            DohEndpoint(name="cloudflare", url="https://cloudflare-dns.com/dns-query"),
            DohEndpoint(name="google", url="https://dns.google/resolve"),
            DohEndpoint(name="quad9", url="https://dns.quad9.net:5053/dns-query"),
        ]
    )
    bogus_resolver_ip: str = "192.0.2.1"
    bogus_probe_name: str = "cloudflare.com"


class PathDiversityConfig(BaseModel):
    targets: list[HostSpec] = Field(
        default_factory=lambda: [
            HostSpec(label="cloudflare", host="cloudflare.com"),
            HostSpec(label="discord", host="discord.com"),
        ]
    )
    max_targets: int = 3


class Output(BaseModel):
    logs_dir: str = "./logs"
    cache_dir: str = "./.cache"
    emoji: bool = True
    formats: list[str] = Field(default_factory=lambda: ["md"])

    @field_validator("formats")
    @classmethod
    def _normalize_formats(cls, value: list[str]) -> list[str]:
        tokens = [str(v).strip().lower() for v in value]
        if "all" in tokens:
            tokens = list(FORMAT_EXTENSIONS)
        seen: list[str] = []
        for token in tokens:
            if token not in FORMAT_EXTENSIONS:
                raise ValueError(
                    f"unknown output format {token!r}; expected one of "
                    f"{sorted(FORMAT_EXTENSIONS)} or 'all'"
                )
            if token not in seen:
                seen.append(token)
        return seen


class Watch(BaseModel):
    interval_seconds: int = 60
    speedtest_every_n_cycles: int = 10
    dashboard_refresh_hz: int = 4


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETSLEUTH_",
        env_nested_delimiter="__",
        env_file_encoding="utf-8",
        extra="ignore",
        yaml_file=None,
    )

    timeouts: Timeouts = Timeouts()
    probing: Probing = Probing()
    speedtest: Speedtest = Speedtest()
    providers: Providers = Providers()
    dnsbl: Dnsbl = Dnsbl()
    thresholds: Thresholds = Thresholds()
    output: Output = Output()
    watch: Watch = Watch()
    tls: TlsConfig = TlsConfig()
    prefix_bench: PrefixBenchConfig = PrefixBenchConfig()
    dpi_check: DpiCheckConfig = DpiCheckConfig()
    dns_advanced: DnsAdvancedConfig = DnsAdvancedConfig()
    path_diversity: PathDiversityConfig = PathDiversityConfig()

    ipinfo_token: SecretStr | None = Field(default=None, alias="IPINFO_TOKEN")
    peeringdb_api_key: SecretStr | None = Field(default=None, alias="PEERINGDB_API_KEY")
    abuseipdb_api_key: SecretStr | None = Field(default=None, alias="ABUSEIPDB_API_KEY")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


def load_settings(
    config_path: Path | None = None,
    env_file: Path | None = None,
) -> Settings:
    yaml_path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    dotenv_path = Path(env_file) if env_file is not None else DEFAULT_ENV_PATH
    Settings.model_config["yaml_file"] = yaml_path if yaml_path.exists() else None
    kwargs: dict[str, Any] = {"_env_file": str(dotenv_path) if dotenv_path.exists() else None}
    return Settings(**kwargs)
