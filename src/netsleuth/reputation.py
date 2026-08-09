from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

import dns.asyncresolver
import dns.exception
import httpx

from netsleuth.config import Providers
from netsleuth.models import DnsblHit, InternetDbResult, Reputation


def parse_netset(text: str) -> list[str]:
    entries: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(stripped)
    return entries


class NetsetIndex:
    def __init__(self) -> None:
        # Sorted (start, end, name) ranges per address family; a lookup is one
        # bisect plus a short backward scan, which beats a per-CIDR loop over
        # the ~1M prefixes a full FireHOL set contains.
        self._ranges: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._dirty = False

    def add(self, name: str, cidrs: list[str]) -> None:
        for entry in cidrs:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            self._ranges[network.version].append(
                (int(network.network_address), int(network.broadcast_address), name)
            )
        self._dirty = True

    def _reindex(self) -> None:
        for version in (4, 6):
            self._ranges[version].sort()
            self._starts[version] = [start for start, _, _ in self._ranges[version]]
        self._dirty = False

    def hits(self, ip: str) -> list[str]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if self._dirty:
            self._reindex()
        version = address.version
        value = int(address)
        found: list[str] = []
        position = bisect_right(self._starts[version], value)
        for start, end, name in reversed(self._ranges[version][:position]):
            if end >= value and name not in found:
                found.append(name)
        return found


async def refresh_netsets(
    client: httpx.AsyncClient,
    providers: Providers,
    cache_dir: Path,
) -> NetsetIndex:
    directory = Path(cache_dir) / "firehol"
    directory.mkdir(parents=True, exist_ok=True)
    index = NetsetIndex()
    for url in providers.firehol_netsets:
        name = url.rsplit("/", 1)[-1].removesuffix(".netset")
        path = directory / f"{name}.netset"
        fresh = (
            path.exists()
            and (time.time() - os.path.getmtime(path)) < providers.firehol_refresh_hours * 3600
        )
        if not fresh:
            try:
                response = await client.get(url)
                response.raise_for_status()
                tmp = path.with_suffix(".netset.tmp")
                tmp.write_text(response.text, encoding="utf-8")
                os.replace(tmp, path)
            except httpx.HTTPError:
                if not path.exists():
                    continue
        index.add(name, parse_netset(path.read_text(encoding="utf-8")))
    return index


# Spamhaus (and its mirrors) return codes in 127.255.255.0/24 to signal a
# problem with the QUERY, not a property of the queried IP. .254 means the
# question arrived via a public resolver, which is the normal case for anyone
# on 1.1.1.1 or 8.8.8.8; .255 means rate limited. Reading either as "listed"
# red-flags most users, which is exactly the false positive this decoder exists
# to prevent.
DNSBL_ERROR_PREFIX = "127.255.255."
_ERROR_REASONS = {
    "127.255.255.254": "query_via_public_resolver",
    "127.255.255.255": "rate_limited",
}


@dataclass
class DnsblOutcome:
    zone: str
    listed: bool = False
    codes: list[str] = field(default_factory=list)
    unavailable_reason: str | None = None


def reverse_ip(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        raise ValueError("classic DNSBL zones accept IPv4 only")
    return ".".join(reversed(str(address).split(".")))


def decode_dnsbl(zone: str, answers: list[str]) -> DnsblOutcome:
    codes = list(answers)
    errors = [code for code in codes if code.startswith(DNSBL_ERROR_PREFIX)]
    if errors:
        return DnsblOutcome(
            zone=zone,
            listed=False,
            codes=codes,
            unavailable_reason=_ERROR_REASONS.get(errors[0], "provider_error"),
        )
    listed = any(code.startswith("127.") for code in codes)
    return DnsblOutcome(zone=zone, listed=listed, codes=codes, unavailable_reason=None)


def summarize_dnsbl(outcomes: list[DnsblOutcome]) -> tuple[list[DnsblHit], bool]:
    hits = [
        DnsblHit(zone=o.zone, codes=o.codes, meaning="listed")
        for o in outcomes
        if o.listed
    ]
    blocked = any(o.unavailable_reason is not None for o in outcomes)
    return hits, blocked


def normalize_internetdb(payload: dict) -> InternetDbResult:
    if "ip" not in payload:
        return InternetDbResult()
    return InternetDbResult(
        ip=payload.get("ip"),
        ports=list(payload.get("ports") or []),
        hostnames=list(payload.get("hostnames") or []),
        tags=list(payload.get("tags") or []),
        cpes=list(payload.get("cpes") or []),
        vulns=list(payload.get("vulns") or []),
    )


def captcha_risk(
    firehol_hits: list[str],
    dnsbl_hits: list[DnsblHit],
    ip_type: str,
    abuseipdb_score: int | None,
) -> tuple[str, str]:
    risk, rationale, _ = _captcha_risk_full(firehol_hits, dnsbl_hits, ip_type, abuseipdb_score)
    return risk, rationale


def _captcha_risk_full(
    firehol_hits: list[str],
    dnsbl_hits: list[DnsblHit],
    ip_type: str,
    abuseipdb_score: int | None,
) -> tuple[str, str, str]:
    reasons: list[str] = []
    reasons_ru: list[str] = []
    risk = "low"
    if firehol_hits:
        risk = "high"
        reasons.append(f"listed on {', '.join(firehol_hits)}")
        reasons_ru.append(f"в блоклисте {', '.join(firehol_hits)}")
    if dnsbl_hits:
        risk = "high"
        reasons.append(f"listed on {', '.join(h.zone for h in dnsbl_hits)}")
        reasons_ru.append(f"в блоклисте {', '.join(h.zone for h in dnsbl_hits)}")
    if abuseipdb_score is not None and abuseipdb_score >= 50:
        risk = "high"
        reasons.append(f"AbuseIPDB confidence {abuseipdb_score}")
        reasons_ru.append(f"уверенность AbuseIPDB {abuseipdb_score}")
    elif abuseipdb_score is not None and abuseipdb_score >= 25 and risk == "low":
        risk = "medium"
        reasons.append(f"AbuseIPDB confidence {abuseipdb_score}")
        reasons_ru.append(f"уверенность AbuseIPDB {abuseipdb_score}")
    if risk == "low" and ip_type == "hosting":
        risk = "medium"
        reasons.append("egress looks like hosting/proxy space, which many sites challenge by default")
        reasons_ru.append("исходящий адрес похож на хостинг/прокси-пространство, которое многие сайты по умолчанию проверяют капчей")
    if not reasons:
        reasons.append("no blocklist match and the address looks like ordinary end-user space")
        reasons_ru.append("совпадений с блоклистами нет, адрес выглядит как обычное пользовательское пространство")
    return risk, "; ".join(reasons), "; ".join(reasons_ru)


@dataclass
class ReputationContext:
    ip_type: str
    internetdb: InternetDbResult | None
    firehol_hits: list[str]
    dnsbl_outcomes: list[DnsblOutcome] | None
    abuseipdb_score: int | None
    abuseipdb_reports: int | None


def build_reputation(ctx: ReputationContext) -> Reputation:
    hits: list[DnsblHit] | None = None
    blocked = False
    if ctx.dnsbl_outcomes is not None:
        hits, blocked = summarize_dnsbl(ctx.dnsbl_outcomes)
    risk, rationale, rationale_ru = _captcha_risk_full(ctx.firehol_hits, hits or [], ctx.ip_type, ctx.abuseipdb_score)
    return Reputation(
        internetdb=ctx.internetdb,
        firehol_hits=ctx.firehol_hits,
        dnsbl_hits=hits,
        dnsbl_query_blocked=blocked,
        abuseipdb_score=ctx.abuseipdb_score,
        abuseipdb_reports=ctx.abuseipdb_reports,
        captcha_risk=risk,
        rationale=rationale,
        rationale_ru=rationale_ru,
    )


async def query_dnsbl(ip: str, zones: list[str], timeout: float) -> list[DnsblOutcome]:
    label = reverse_ip(ip)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    async def one(zone: str) -> DnsblOutcome:
        try:
            answer = await resolver.resolve(f"{label}.{zone}", "A")
        except dns.exception.DNSException:
            return DnsblOutcome(zone=zone, listed=False, codes=[])
        return decode_dnsbl(zone, sorted(record.address for record in answer))

    return list(await asyncio.gather(*(one(zone) for zone in zones)))


async def fetch_internetdb(client: httpx.AsyncClient, providers: Providers, ip: str) -> dict:
    response = await client.get(f"{providers.internetdb_url}{ip}")
    if response.status_code == 404:
        return {"detail": "No information available"}
    response.raise_for_status()
    return response.json()


async def fetch_abuseipdb(
    client: httpx.AsyncClient, providers: Providers, ip: str, key: str
) -> dict:
    response = await client.get(
        providers.abuseipdb_url,
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        headers={"Key": key, "Accept": "application/json"},
    )
    response.raise_for_status()
    return response.json()
