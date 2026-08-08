from __future__ import annotations

import ipaddress
import os
import time
from bisect import bisect_right
from pathlib import Path

import httpx

from netcheck.config import Providers


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
