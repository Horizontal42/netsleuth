from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def api_fixture():
    def _load(name: str) -> dict:
        return json.loads((FIXTURES / "api" / name).read_text(encoding="utf-8"))

    return _load


@pytest.fixture(scope="session")
def trace_fixture():
    def _load(os_dir: str, name: str, encoding: str = "utf-8") -> str:
        return (FIXTURES / "traceroute" / os_dir / name).read_bytes().decode(encoding)

    return _load
