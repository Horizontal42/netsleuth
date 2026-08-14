from __future__ import annotations

import re
from pathlib import Path

from netsleuth.exporter import egress_asn, sanitize_name

_REPORT_NAME_RE = re.compile(r"^report_(?P<key>.+)_(?P<ts>\d{2}-\d{2}-\d{2}Z)\.json$")


def report_key(meta: dict, report: dict) -> str | None:
    return meta.get("target") or egress_asn(report)


def matching_reports(paths: list[Path], key: str, *, exclude: str | None = None) -> list[Path]:
    prefix = f"report_{sanitize_name(key)}_"
    # Filenames only carry a time-of-day now (the date lives in the YYYY/MM/DD
    # directory), so recency must be sorted on the full path, not the basename.
    candidates = [p for p in paths if p.name.startswith(prefix) and p.name.endswith(".json") and p.name != exclude]
    return sorted(candidates, key=lambda p: p.as_posix(), reverse=True)


def find_previous(
    logs_dir: Path | str, key: str, *, exclude: str | None = None, limit: int | None = None
) -> list[Path]:
    logs_dir = Path(logs_dir)
    if not logs_dir.is_dir():
        return []
    ordered = matching_reports(list(logs_dir.rglob("report_*.json")), key, exclude=exclude)
    return ordered[:limit] if limit else ordered


def latest_key(logs_dir: Path | str) -> str | None:
    logs_dir = Path(logs_dir)
    if not logs_dir.is_dir():
        return None
    for path in sorted(logs_dir.rglob("report_*.json"), key=lambda p: p.as_posix(), reverse=True):
        match = _REPORT_NAME_RE.match(path.name)
        if match:
            return match.group("key")
    return None
