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
