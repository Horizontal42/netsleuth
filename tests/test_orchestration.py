from __future__ import annotations

import asyncio

import httpx
import pytest

from netcheck.models import ModuleResult, ProbeError
from netcheck.orchestration import classify_exception, gather_modules, run_module


def test_classify_timeout_errors():
    assert classify_exception(asyncio.TimeoutError()) == ("timeout", True)
    assert classify_exception(httpx.ConnectTimeout("slow")) == ("timeout", True)
    assert classify_exception(TimeoutError()) == ("timeout", True)


def test_classify_http_status_errors_by_code():
    def err(code: int) -> httpx.HTTPStatusError:
        request = httpx.Request("GET", "https://example.test/")
        response = httpx.Response(code, request=request)
        return httpx.HTTPStatusError("boom", request=request, response=response)

    assert classify_exception(err(429)) == ("rate_limited", True)
    assert classify_exception(err(403)) == ("blocked", False)
    assert classify_exception(err(451)) == ("blocked", False)
    assert classify_exception(err(500)) == ("http_error", True)
    assert classify_exception(err(404)) == ("http_error", False)


def test_classify_transport_and_parse_and_privilege_errors():
    assert classify_exception(httpx.ConnectError("refused")) == ("unavailable", True)
    assert classify_exception(OSError("network unreachable")) == ("unavailable", True)
    assert classify_exception(ValueError("bad json")) == ("parse_error", False)
    assert classify_exception(KeyError("asn")) == ("parse_error", False)
    assert classify_exception(PermissionError("raw socket")) == ("no_privilege", False)
    assert classify_exception(NotImplementedError("no win api here")) == ("not_applicable", False)


def test_classify_unknown_exception_falls_back_to_unavailable():
    class Weird(Exception):
        pass

    assert classify_exception(Weird("?")) == ("unavailable", False)


async def test_run_module_returns_ok_envelope_on_success():
    async def work():
        await asyncio.sleep(0)
        return {"value": 42}

    result = await run_module("bgp", work(), timeout=1.0)
    assert isinstance(result, ModuleResult)
    assert result.name == "bgp"
    assert result.status == "ok"
    assert result.data == {"value": 42}
    assert result.errors == []
    assert result.started_at.endswith("Z")
    assert result.duration_ms >= 0


async def test_run_module_passes_through_a_module_result_unchanged_but_timed():
    async def work():
        return ModuleResult(name="reputation", status="partial", data={"x": 1}, warnings=["no key"])

    result = await run_module("reputation", work(), timeout=1.0)
    assert result.status == "partial"
    assert result.warnings == ["no key"]
    assert result.started_at.endswith("Z")


async def test_run_module_converts_an_exception_into_a_failed_envelope():
    async def work():
        raise httpx.ConnectError("refused")

    result = await run_module("ip_geo", work(), timeout=1.0, source="ip-api")
    assert result.status == "failed"
    assert result.data is None
    assert result.errors == [
        ProbeError(source="ip-api", kind="unavailable", message="refused", retryable=True)
    ]


async def test_run_module_enforces_its_own_timeout():
    async def work():
        await asyncio.sleep(5)

    result = await run_module("speed", work(), timeout=0.05)
    assert result.status == "failed"
    assert result.errors[0].kind == "timeout"
    assert result.duration_ms < 2000


async def test_run_module_lets_cancellation_propagate():
    async def work():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_module("latency", work(), timeout=1.0)


async def test_run_module_catches_base_exceptions_other_than_cancellation():
    # A literal KeyboardInterrupt can't be used here: CPython's asyncio.Task
    # special-cases KeyboardInterrupt/SystemExit and re-raises them straight
    # into the event loop's callback processing (in addition to setting them
    # as the task's exception), which crashes asyncio.run() regardless of any
    # `except BaseException` in the awaiting coroutine. A plain BaseException
    # subclass exercises the same "not Exception, not CancelledError" path
    # without hitting that special case.
    class NonCancelBaseException(BaseException):
        pass

    async def work():
        raise NonCancelBaseException()

    result = await run_module("dns_leak", work(), timeout=1.0)
    assert result.status == "failed"
    assert result.errors[0].kind == "unavailable"


async def test_gather_modules_never_raises_and_preserves_order():
    async def ok():
        return ModuleResult(name="a", status="ok", data=1)

    async def boom():
        raise RuntimeError("nope")

    results = await gather_modules(
        run_module("a", ok(), timeout=1.0),
        run_module("b", boom(), timeout=1.0),
    )
    assert [r.name for r in results] == ["a", "b"]
    assert [r.status for r in results] == ["ok", "failed"]
