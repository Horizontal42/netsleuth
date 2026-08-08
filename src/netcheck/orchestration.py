from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Awaitable

import httpx

from netcheck.models import ModuleResult, ProbeError

_BLOCKED_STATUS = {401, 403, 451}
_RETRYABLE_STATUS_FLOOR = 500


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_exception(exc: BaseException) -> tuple[str, bool]:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException)):
        return "timeout", True
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code == 429:
            return "rate_limited", True
        if code in _BLOCKED_STATUS:
            return "blocked", False
        return "http_error", code >= _RETRYABLE_STATUS_FLOOR
    if isinstance(exc, PermissionError):
        return "no_privilege", False
    if isinstance(exc, NotImplementedError):
        return "not_applicable", False
    if isinstance(exc, (httpx.TransportError, ConnectionError, OSError)):
        return "unavailable", True
    if isinstance(exc, (ValueError, KeyError, TypeError, IndexError, AttributeError)):
        return "parse_error", False
    return "unavailable", False


async def run_module(
    name: str,
    coro: Awaitable[Any],
    *,
    timeout: float,
    source: str | None = None,
) -> ModuleResult:
    started_at = utc_now_iso()
    began = time.perf_counter()
    try:
        value = await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.CancelledError:
        raise
    except BaseException as exc:  # noqa: BLE001 - failure is a value here, not control flow
        kind, retryable = classify_exception(exc)
        message = str(exc) or exc.__class__.__name__
        result = ModuleResult(
            name=name,
            status="failed",
            errors=[ProbeError(source=source or name, kind=kind, message=message, retryable=retryable)],
        )
    else:
        if isinstance(value, ModuleResult):
            result = value
        else:
            result = ModuleResult(name=name, status="ok", data=value)
    result.name = name
    result.started_at = started_at
    result.duration_ms = int((time.perf_counter() - began) * 1000)
    return result


async def gather_modules(*results: Awaitable[ModuleResult]) -> list[ModuleResult]:
    gathered = await asyncio.gather(*results, return_exceptions=True)
    out: list[ModuleResult] = []
    for item in gathered:
        if isinstance(item, ModuleResult):
            out.append(item)
            continue
        if isinstance(item, asyncio.CancelledError):
            raise item
        kind, retryable = classify_exception(item)
        out.append(
            ModuleResult(
                name="unknown",
                status="failed",
                errors=[ProbeError(source="orchestration", kind=kind, message=str(item), retryable=retryable)],
            )
        )
    return out
