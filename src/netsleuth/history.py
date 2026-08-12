from __future__ import annotations

import re
from pathlib import Path

from netsleuth.exporter import egress_asn, sanitize_name

_REPORT_NAME_RE = re.compile(r"^report_(?P<key>.+)_(?P<ts>\d{8}T\d{6}Z)\.json$")


def report_key(meta: dict, report: dict) -> str | None:
    return meta.get("target") or egress_asn(report)


def matching_reports(names: list[str], key: str, *, exclude: str | None = None) -> list[str]:
    prefix = f"report_{sanitize_name(key)}_"

    def _timestamp(name: str) -> str:
        match = _REPORT_NAME_RE.match(name)
        return match.group("ts") if match else ""

    candidates = [n for n in names if n.startswith(prefix) and n.endswith(".json") and n != exclude]
    return sorted(candidates, key=_timestamp, reverse=True)


def find_previous(
    logs_dir: Path | str, key: str, *, exclude: str | None = None, limit: int | None = None
) -> list[Path]:
    logs_dir = Path(logs_dir)
    if not logs_dir.is_dir():
        return []
    names = [p.name for p in logs_dir.glob("report_*.json")]
    ordered = matching_reports(names, key, exclude=exclude)
    paths = [logs_dir / name for name in ordered]
    return paths[:limit] if limit else paths


def latest_key(logs_dir: Path | str) -> str | None:
    logs_dir = Path(logs_dir)
    if not logs_dir.is_dir():
        return None
    for path in sorted(logs_dir.glob("report_*.json"), key=lambda p: p.name, reverse=True):
        match = _REPORT_NAME_RE.match(path.name)
        if match:
            return match.group("key")
    return None
