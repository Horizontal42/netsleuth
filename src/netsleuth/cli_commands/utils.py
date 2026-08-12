"""Shared CLI utilities and helpers."""

from __future__ import annotations

import os
import platform
import socket
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

import httpx
import psutil
import typer
from rich.console import Console

from netsleuth import __version__
from netsleuth.config import FORMAT_EXTENSIONS, Settings, load_settings
from netsleuth.models import BindTarget, Finding


@dataclass
class Options:
    """CLI options container."""

    mode: str = "auto"
    target_kind: str | None = None
    target_value: str | None = None
    quick: bool = False
    full: bool = False
    extra_host: str | None = None
    speedtest_server: str | None = None
    dnsbl: bool = False
    ndt7: bool = False
    tcp_trace: bool = False
    tls: bool = False
    dns_advanced: bool = False
    path_diversity: bool = False
    prefix_bench: bool = False
    dpi_target: str | None = None
    formats: frozenset[str] = frozenset({"md"})
    interface: str | None = None
    bind: BindTarget | None = None


def parse_formats(
    values: list[str], ru: bool, json_flag: bool, default: frozenset[str]
) -> frozenset[str]:
    """Parse output format options from CLI arguments."""
    tokens = [t.strip().lower() for raw in values for t in raw.split(",") if t.strip()]
    if ru:
        tokens.append("ru-md")
    if json_flag:
        tokens.append("json")
    if not tokens:
        return default
    if "none" in tokens:
        if len(set(tokens)) > 1:
            raise typer.BadParameter("'none' cannot be combined with other formats.")
        return frozenset()
    if "all" in tokens:
        return frozenset(FORMAT_EXTENSIONS)
    unknown = sorted(set(tokens) - set(FORMAT_EXTENSIONS))
    if unknown:
        raise typer.BadParameter(
            f"unknown format(s) {unknown}; expected one of {sorted(FORMAT_EXTENSIONS)}, 'all' or 'none'"
        )
    return frozenset(tokens)


def format_siblings(values: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize format sibling options."""
    return tuple(v.strip() for v in values if v.strip())


def parse_target(value: str) -> tuple[str, str]:
    """Parse target specification (e.g., 'ip:8.8.8.8' or 'host:example.com')."""
    if ":" not in value:
        raise typer.BadParameter(f"invalid target {value!r}; expected format '<kind>:<value>'")
    kind, _, rest = value.partition(":")
    if not kind or not rest:
        raise typer.BadParameter(f"invalid target {value!r}; expected format '<kind>:<value>'")
    if kind not in ("ip", "host", "prefix"):
        raise typer.BadParameter(f"unknown target kind {kind!r}; expected 'ip', 'host', or 'prefix'")
    return kind, rest


def _os_timezone() -> str | None:
    """Get the OS timezone name."""
    try:
        if sys.platform == "win32":
            import winreg

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
            tz_name, _ = winreg.QueryValueEx(key, "TimeZoneKeyName")
            return tz_name
        else:
            timezone = os.readlink("/etc/localtime")
            if "zoneinfo" in timezone:
                return timezone.split("zoneinfo/")[-1]
    except Exception:
        pass
    return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by id, keeping the first occurrence."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen:
            seen[f.id] = f
    return list(seen.values())


# Re-export commonly used objects
console = Console()
app = typer.Typer(add_completion=False, help="Deep network diagnostics.")
