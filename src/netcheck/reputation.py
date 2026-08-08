from __future__ import annotations

import ipaddress
import os
import time
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from netcheck.config import Providers
from netcheck.models import DnsblHit


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
