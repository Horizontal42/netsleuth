from __future__ import annotations

import math
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

ERROR_KINDS = (
    "timeout",
    "http_error",
    "rate_limited",
    "blocked",
    "parse_error",
    "unavailable",
    "no_privilege",
    "not_applicable",
)
STATUSES = ("ok", "partial", "failed", "skipped")
SEVERITIES = ("ok", "info", "warn", "crit")
DIRECTIONS = ("vpn", "clean")


@dataclass
class ProbeError:
    source: str
    kind: str
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        if self.kind not in ERROR_KINDS:
            raise ValueError(f"unknown ProbeError kind: {self.kind!r}")


@dataclass
class ModuleResult:
    name: str
    status: str
    data: Any | None = None
    errors: list[ProbeError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    started_at: str = ""
    duration_ms: int = 0

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown ModuleResult status: {self.status!r}")


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    metric: str | None = None
    value: float | str | None = None
    threshold: float | str | None = None
    advice: str | None = None
    title_ru: str | None = None
    detail_ru: str | None = None
    advice_ru: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown Finding severity: {self.severity!r}")


@dataclass
class Signal:
    name: str
    observed: bool
    weight: float
    direction: str
    note: str = ""

    def __post_init__(self) -> None:
        if self.direction not in DIRECTIONS:
            raise ValueError(f"unknown Signal direction: {self.direction!r}")


@dataclass
class Capabilities:
    os_name: str = ""
    is_elevated: bool = False
    icmp_dgram: bool = False
    icmp_raw: bool = False
    icmp_win_api: bool = False
    mtr_binary: str | None = None
    traceroute_binary: str | None = None
    chosen_latency_backend: str = "none"
    chosen_trace_backend: str = "none"
    notes: list[str] = field(default_factory=list)


@dataclass
class BindTarget:
    requested: str
    iface_name: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    is_up: bool = False
    error: str | None = None


@dataclass
class LocalNet:
    iface_name: str | None = None
    local_ipv4: str | None = None
    local_ipv6: str | None = None
    iface_mtu: int | None = None
    default_gateway_v4: str | None = None
    default_gateway_v6: str | None = None
    dns_servers_per_adapter: dict[str, list[str]] = field(default_factory=dict)
    is_dual_stack: bool = False


@dataclass
class IpGeo:
    ip: str | None = None
    ip_version: int | None = None
    reverse_dns: str | None = None
    asn: str | None = None
    as_name: str | None = None
    org: str | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    ip_type: str = "unknown"
    sources: dict[str, str] = field(default_factory=dict)


@dataclass
class CfTrace:
    ip: str | None = None
    colo: str | None = None
    loc: str | None = None
    warp: str | None = None
    gateway: str | None = None
    rbi: str | None = None
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class AdapterLeakResult:
    adapter: str
    configured_resolvers: list[str] = field(default_factory=list)
    echoed_ip: str | None = None
    echoed_asn: str | None = None
    matches_egress_asn: bool | None = None


@dataclass
class DnsLeak:
    per_adapter: list[AdapterLeakResult] = field(default_factory=list)
    ecs_leaked: bool = False
    note: str = ""
    note_ru: str | None = None


@dataclass
class VpnContext:
    local: LocalNet
    geo: IpGeo
    cf: CfTrace | None = None
    dns_leak: DnsLeak | None = None
    pdb_info_type: str | None = None
    os_timezone: str | None = None
    provider_flags: dict[str, bool] = field(default_factory=dict)


@dataclass
class VpnAssessment:
    verdict: str = "none"
    confidence: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    tunnel_iface: str | None = None
    dns_leak: DnsLeak | None = None


@dataclass
class BgpEvent:
    timestamp: str
    type: str
    prefix: str | None = None
    path: list[int] = field(default_factory=list)


@dataclass
class IxpPresence:
    name: str
    city: str | None = None
    country: str | None = None
    speed_mbps: int | None = None


@dataclass
class BgpIntel:
    asn: str | None = None
    holder: str | None = None
    registry: str | None = None
    allocated_at: str | None = None
    upstreams: list[str] = field(default_factory=list)
    peers: list[str] = field(default_factory=list)
    downstreams: list[str] = field(default_factory=list)
    announced_prefixes: list[str] = field(default_factory=list)
    prefix_count_v4: int = 0
    prefix_count_v6: int = 0
    flaps: list[BgpEvent] = field(default_factory=list)
    stability: str = "unknown"
    ixps: list[IxpPresence] = field(default_factory=list)
    pdb_info_type: str | None = None
    pdb_traffic: str | None = None
    asrank: int | None = None
    cone_asns: int | None = None
    cone_prefixes: int | None = None


@dataclass
class InternetDbResult:
    ip: str | None = None
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)


@dataclass
class DnsblHit:
    zone: str
    codes: list[str] = field(default_factory=list)
    meaning: str = "listed"


@dataclass
class Reputation:
    internetdb: InternetDbResult | None = None
    firehol_hits: list[str] = field(default_factory=list)
    dnsbl_hits: list[DnsblHit] | None = None
    dnsbl_query_blocked: bool = False
    abuseipdb_score: int | None = None
    abuseipdb_reports: int | None = None
    captcha_risk: str = "low"
    rationale: str = ""
    rationale_ru: str | None = None


@dataclass
class PingResult:
    label: str
    host: str
    resolved_ip: str | None = None
    method: str = "none"
    sent: int = 0
    received: int = 0
    loss_pct: float = 0.0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    mdev_ms: float | None = None
    jitter_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None
    cv: float | None = None
    samples: list[float | None] = field(default_factory=list)


@dataclass
class TraceConfig:
    target: str
    resolved_ip: str | None
    backend: str = "system_traceroute"
    max_hops: int = 30


@dataclass
class TraceHop:
    ttl: int
    ip: str | None = None
    reverse_dns: str | None = None
    asn: str | None = None
    as_name: str | None = None
    probes: list[float | None] = field(default_factory=list)
    loss_pct: float = 0.0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None
    annotations: list[str] = field(default_factory=list)


@dataclass
class TraceResult:
    target: str | None = None
    resolved_ip: str | None = None
    backend: str = "none"
    hops: list[TraceHop] = field(default_factory=list)
    cycles: int = 0
    completed: bool = False
    max_hops_reached: bool = False


@dataclass
class TierAttempt:
    tier: str
    ok: bool
    reason: str | None = None
    duration_ms: int = 0


@dataclass
class CfL4Stats:
    rtt_ms: float | None = None
    min_rtt_ms: float | None = None
    rtt_var_ms: float | None = None
    delivery_rate_bps: int | None = None
    cwnd: int | None = None
    unsent_bytes: int | None = None
    recv_bytes: int | None = None


@dataclass
class SpeedResult:
    method: str = "none"
    tier_attempts: list[TierAttempt] = field(default_factory=list)
    download_mbps: float | None = None
    upload_mbps: float | None = None
    server: str | None = None
    idle_rtt_ms: float | None = None
    loaded_rtt_down_ms: float | None = None
    loaded_rtt_up_ms: float | None = None
    bufferbloat_down_ms: float | None = None
    bufferbloat_up_ms: float | None = None
    bufferbloat_grade: str | None = None
    cfL4_stats: CfL4Stats | None = None
    netflix_oca_onnet: bool | None = None


def to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, bool, int)):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(v) for v in obj)
    if isinstance(obj, Enum):
        return to_jsonable(obj.value)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    return str(obj)
