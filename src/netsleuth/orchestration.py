from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Awaitable

import httpx

from netsleuth.models import ModuleResult, ProbeError

_BLOCKED_STATUS = {401, 403, 451}
_RETRYABLE_STATUS_FLOOR = 500


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format.

    Returns:
        A string like '2025-01-15T14:30:00Z' representing the current UTC time.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_exception(exc: BaseException) -> tuple[str, bool]:
    """Classify an exception into a probe error kind and retryability.

    Maps exceptions to one of the standard error kinds defined in models.py
    and determines whether the operation should be retried.

    Args:
        exc: The exception to classify.

    Returns:
        A tuple of (kind, retryable) where kind is one of the ERROR_KINDS
        values and retryable indicates whether the operation might succeed
        if retried.

    Examples:
        >>> classify_exception(asyncio.TimeoutError())
        ('timeout', True)
        >>> classify_exception(PermissionError())
        ('no_privilege', False)
    """
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
    """Execute a probe module with timeout and error handling.

    Runs the given coroutine with a timeout, catching any exceptions and
    converting them into structured ProbeError objects. Tracks execution
    timing and ensures the result has consistent metadata.

    Args:
        name: The module name for identification in results.
        coro: The coroutine to execute (typically an async probe function).
        timeout: Maximum time in seconds to wait for the coroutine.
        source: Optional source identifier for errors; defaults to name.

    Returns:
        A ModuleResult with status 'ok', 'partial', or 'failed', containing
        either the probe data or structured error information.

    Raises:
        asyncio.CancelledError: Propagated without modification.
    """
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
    """Run multiple modules concurrently and collect their results.

    Executes all provided coroutines in parallel using asyncio.gather,
    converting any exceptions into failed ModuleResult objects so that
    one failing module doesn't prevent others from completing.

    Args:
        *results: Variable number of awaitable ModuleResult coroutines.

    Returns:
        A list of ModuleResult objects, one for each input coroutine.
        Failed coroutines are represented as ModuleResult with status 'failed'.

    Raises:
        asyncio.CancelledError: Propagated without modification.
    """
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
