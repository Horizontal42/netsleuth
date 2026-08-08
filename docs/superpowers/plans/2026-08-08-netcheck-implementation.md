# netcheck Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `netcheck`, a cross-platform Python 3.10+ CLI that deeply diagnoses the local network connection (or a target ASN/IP/domain) and emits a human-readable Markdown report plus a complete machine-readable JSON dump per run.

**Architecture:** An async orchestrator (`cli.py`) runs typed probe modules in dependency-ordered phases, each wrapped by a single `run_module()` envelope that turns every failure into a `ModuleResult` value rather than an exception. Data collection (`netinfo`, `ip_geo`, `bgp`, `reputation`, `probes/*`, `speed`) is strictly separated from interpretation (`interpret.py`, pure functions over collected data) and from rendering (`exporter.py`). Every OS-specific path is a cascade with an unprivileged default and text parsing only as a last resort.

**Tech Stack:** Python 3.10+, Typer, Rich, httpx[http2], pydantic v2 + pydantic-settings (YamlConfigSettingsSource), PyYAML, dnspython, psutil, icmplib (Unix), ctypes `Iphlpapi.dll` (Windows). Dev: uv, pytest, pytest-asyncio, pytest-httpx.

**Source spec:** `docs/superpowers/specs/2026-08-08-netcheck-design.md` (approved 2026-08-08). Section references below (`§4`, `§9`, …) point into it.

## Global Constraints

- **Python floor:** 3.10. No `match` on structural patterns requiring 3.11+, no `typing.Self`, no `ExceptionGroup`. `X | None` unions in annotations are fine (PEP 604 is 3.10).
- **Dependency source of truth:** `pyproject.toml` + `uv.lock`, managed with `uv`. `requirements.txt` is a *generated* artifact (`uv export --no-hashes --format requirements-txt -o requirements.txt`), never hand-edited.
- **Base dependencies (exact floors from spec §17):** `typer>=0.12`, `rich>=13.7`, `httpx[http2]>=0.28`, `pydantic>=2.7`, `pydantic-settings>=2.3`, `pyyaml>=6.0`, `dnspython>=2.6`, `psutil>=5.9`, `icmplib>=3.0`. Optional extras: `tcptrace = ["scapy>=2.5"]`, `ndt7 = ["websockets>=12"]`. Dev: `pytest>=8`, `pytest-asyncio>=0.23`, `pytest-httpx>=0.30`.
- **No Ookla pip package.** `speedtest-cli` is archived; the native `speedtest` binary is detected on PATH, never installed.
- **File size:** keep every module under ~200 lines. One responsibility per module. If a module in this plan grows past that during implementation, split it and note the split in ARCHITECTURE.md — do not let it sprawl.
- **Config split:** secrets (`IPINFO_TOKEN`, `PEERINGDB_API_KEY`, `ABUSEIPDB_API_KEY`) live in `.env` only, typed `SecretStr | None = None`. Everything else lives in `config.yaml`. Precedence is **env > .env > config.yaml > default**. A missing key downgrades its enrichment to `status="skipped"` with a warning — it never fails a run.
- **Atomic writes:** anything written under `./logs/` goes through a temp file in the same directory + `os.replace()`. Never write a report in place.
- **JSON strictness:** `json.dumps(..., allow_nan=False)`; `inf`/`NaN` are coerced to `null` before serialization.
- **Failure is a value:** no probe/API failure aborts a run. Four statuses only: `ok`, `partial`, `failed`, `skipped`.
- **Never require elevation** for the default path on any OS.
- **Comments:** none, except where the *why* is non-obvious (locale/code-page handling, Win32 struct layout, protocol quirks). No docstrings restating the function name.
- **Commit messages:** lowercase imperative, scoped by noun, no conventional-commit prefixes, no emoji, no AI-tool traces of any kind (no `Co-Authored-By`, no "Generated with", no "AI-assisted"). Every `git commit -m` string in this plan is already written that way — use it verbatim.
- **Public repo docs:** `README.md` + `README.ru.md` and `ARCHITECTURE.md` + `ARCHITECTURE.ru.md` are all mandatory, cross-linked at the top of each (`[Русский](README.ru.md)` / `[English](README.md)`), full standalone translations — no "see the English version" stubs.
- **English-only** in code identifiers, commit messages, GitHub issues/PRs. Report/UI strings are English.
- **Testing policy:** test real business logic (parsers, normalizers, classifiers, scoring, math, diffing, serialization). Skip tests for glue (live HTTP, real ICMP, Typer wiring, config *loading* beyond precedence, `psutil`/`ctypes` calls, the `--watch` sleep loop). Where a task's subject is glue, the task says so explicitly instead of faking coverage.
- **License:** undecided (MIT vs Polyform Noncommercial, spec §18). Task 1 lands a placeholder `LICENSE` with a `TODO(user)` marker. Do not choose one.

## File Structure

```
netcheck/
  pyproject.toml              # uv-based, dependency source of truth
  uv.lock                     # committed
  requirements.txt            # generated from uv.lock
  config.yaml                 # all non-secret settings (spec §13)
  .env.example                # the three optional keys, nothing else
  .gitignore                  # already present; extended in Task 1
  LICENSE                     # placeholder, TODO(user)
  README.md / README.ru.md
  ARCHITECTURE.md / ARCHITECTURE.ru.md
  TASKS.md                    # outstanding work, written in Task 42
  src/netcheck/
    __init__.py               # __version__
    __main__.py               # python -m netcheck entrypoint
    cli.py                    # Typer app, flags, phase orchestration, Rich progress
    config.py                 # pydantic-settings loader
    models.py                 # all shared dataclasses + to_jsonable()
    orchestration.py          # run_module(), classify_exception()
    netinfo.py                # Capabilities detection + LocalNet facts
    ip_geo.py                 # provider chain + normalizers + merge
    bgp.py                    # RIPEstat / ASRank / Team Cymru / PeeringDB
    reputation.py             # FireHOL netsets + InternetDB + DNSBL decode
    stats.py                  # pure RTT statistics: loss/min/avg/max/mdev/jitter
    traceparse.py             # pure text -> TraceHop parsers (win/linux/darwin)
    interpret.py              # thresholds -> Finding[], VPN scoring, grading
    speed.py                  # cascading speedtest + bufferbloat + cfL4
    exporter.py               # JSON + Markdown, atomic writes to ./logs
    compare.py                # --compare diff of two JSON reports
    watch.py                  # --watch loop + live Rich dashboard
    probes/
      __init__.py
      latency.py              # ping/jitter fan-out + statistics
      traceroute.py           # mtr -> icmp_win -> icmplib -> system binary
      icmp_win.py             # ctypes IcmpSendEcho2 engine (Windows)
      dns_leak.py             # per-adapter resolvers + echo probes + ECS
  tests/
    conftest.py
    test_models.py  test_config.py  test_orchestration.py  test_netinfo.py
    test_stats.py  test_traceparse.py  test_interpret.py
    test_ip_geo_normalize.py  test_bgp.py
    test_dnsbl_decode.py  test_reputation.py
    test_prober_stats.py  test_icmp_win_parse.py
    test_traceroute_cascade.py  test_dns_leak.py
    test_speed_math.py  test_exporter.py  test_compare.py  test_watch.py
    fixtures/traceroute/{windows,linux,darwin}/*.txt
    fixtures/api/*.json
    fixtures/reports/*.json
  logs/                       # gitignored
  docs/superpowers/           # specs + this plan
```

## Task Map

| Phase | Tasks | Deliverable |
|---|---|---|
| 0. Scaffold | 1–2 | Installable skeleton + all four doc files |
| 1. Foundation | 3–8 | models, config, run_module, netinfo |
| 2. Pure logic | 9–16 | stats, traceparse (3 OS + dispatcher), interpret |
| 3. Providers | 17–24 | ip_geo, bgp, reputation |
| 4. Probes | 25–30 | latency, icmp_win, traceroute cascade, dns_leak |
| 5. Speed | 31–33 | cascade, math, bufferbloat |
| 6. Export | 34–36 | exporter: strict JSON, Markdown, failed-section placeholders |
| 7. Orchestration | 37–38 | cli phase pipeline, compare |
| 8. Watch | 39 | watch loop and its time-series artifact |
| 9. Close-out | 40–42 | e2e smoke, docs freshness, TASKS.md |

---

## Phase 0 — Scaffold

### Task 1: Project scaffold, packaging, config files

**Files:**
- Create: `pyproject.toml`, `uv.lock` (generated), `requirements.txt` (generated), `LICENSE`, `.env.example`, `config.yaml`
- Create: `src/netcheck/__init__.py`, `src/netcheck/__main__.py`, `src/netcheck/probes/__init__.py`
- Create: `tests/conftest.py`, `tests/__init__.py` is **not** created (pytest rootdir-based collection, no package)
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: package `netcheck` importable as `src`-layout; `netcheck.__version__: str`; console script `netcheck = "netcheck.cli:main"` (the `main` symbol is implemented in Task 37 — a stub lands here); `tests/conftest.py` exposing fixtures `fixtures_dir: Path` and `api_fixture(name: str) -> dict`.

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "netcheck"
version = "0.1.0"
description = "Cross-platform CLI for deep network diagnostics: ISP/VPN/ASN identity, latency, path and bandwidth"
readme = "README.md"
requires-python = ">=3.10"
authors = [{ name = "netcheck contributors" }]
keywords = ["network", "diagnostics", "traceroute", "bgp", "vpn", "speedtest"]
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "httpx[http2]>=0.28",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "pyyaml>=6.0",
    "dnspython>=2.6",
    "psutil>=5.9",
    "icmplib>=3.0",
]

[project.optional-dependencies]
tcptrace = ["scapy>=2.5"]
ndt7 = ["websockets>=12"]

[project.scripts]
netcheck = "netcheck.cli:main"

[dependency-groups]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "pytest-httpx>=0.30",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/netcheck"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
filterwarnings = ["error::DeprecationWarning:netcheck.*"]
```

- [ ] **Step 2: Extend `.gitignore`**

Append these lines to the existing `.gitignore` (it already has `.claude/`, `logs/`, `.env`, `.venv/`, `__pycache__/`):

```gitignore
# packaging
dist/
build/
*.egg-info/

# netcheck runtime caches
.cache/
```

- [ ] **Step 3: Create the LICENSE placeholder**

`LICENSE`:

```text
LICENSE NOT YET FINALIZED

TODO(user): finalize MIT vs Polyform Noncommercial — see spec §18
(docs/superpowers/specs/2026-08-08-netcheck-design.md).

Context for the decision:
  - netcheck's default reputation sources (Shodan InternetDB, Spamhaus free
    mirrors) are licensed for non-commercial use only.
  - Polyform Noncommercial keeps downstream forks inside those third-party
    terms. MIT does not: a commercial fork would silently violate them.
  - If MIT is chosen anyway, README must state that the default reputation
    sources are non-commercial-use-only and that a commercial fork has to
    swap them.

Until this file is replaced with a real license text, no license is granted.
```

- [ ] **Step 4: Create `.env.example` — secrets only**

```dotenv
# netcheck secrets. Every key here is OPTIONAL: netcheck runs fully with an
# empty .env. A missing key downgrades only the enrichment that needs it.
# Non-secret settings do NOT belong here — they live in config.yaml.

# https://ipinfo.io — enriches geo/ASN. Keyless tier 429s in practice.
IPINFO_TOKEN=

# https://www.peeringdb.com — raises the anonymous 20 req/min limit.
PEERINGDB_API_KEY=

# https://www.abuseipdb.com — abuse confidence score for the egress IP.
ABUSEIPDB_API_KEY=
```

- [ ] **Step 5: Create `config.yaml` with every field from spec §13**

```yaml
timeouts:
  http_seconds: 8.0
  module_seconds: 30.0
  speedtest_seconds: 90.0
  dns_seconds: 4.0
  subprocess_seconds: 60.0

probing:
  reference_hosts:
    - { label: "cloudflare-dns", host: "1.1.1.1" }
    - { label: "google-dns", host: "8.8.8.8" }
    - { label: "quad9-dns", host: "9.9.9.9" }
  service_hosts:
    - { label: "cloudflare", host: "cloudflare.com" }
    - { label: "google", host: "google.com" }
    - { label: "github", host: "github.com" }
  ping_count: 20
  quick_ping_count: 5
  ping_interval_seconds: 0.25
  ping_timeout_seconds: 2.0
  mtr_cycles: 10
  quick_mtr_cycles: 1
  max_hops: 30
  trace_concurrency: 2

speedtest:
  enabled_tiers: ["ookla_bin", "cloudflare", "fastcom"]
  download_sizes_bytes: [1000000, 10000000, 25000000]
  upload_sizes_bytes: [1000000, 5000000]
  cloudflare_base_url: "https://speed.cloudflare.com"
  fastcom_api_url: "https://api.fast.com/netflix/speedtest/v2"
  ndt7_locate_url: "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
  bufferbloat_probe_interval_seconds: 0.2

providers:
  cf_trace_url: "https://www.cloudflare.com/cdn-cgi/trace"
  ip_api_url: "http://ip-api.com/json/"
  freeipapi_url: "https://freeipapi.com/api/json/"
  ipinfo_url: "https://ipinfo.io/"
  ipwhois_url: "https://ipwho.is/"
  ripestat_base_url: "https://stat.ripe.net/data"
  asrank_url: "https://api.asrank.caida.org/v2/graphql"
  peeringdb_base_url: "https://www.peeringdb.com/api"
  internetdb_url: "https://internetdb.shodan.io/"
  abuseipdb_url: "https://api.abuseipdb.com/api/v2/check"
  cymru_origin_zone: "origin.asn.cymru.com"
  cymru_asn_zone: "asn.cymru.com"
  ripestat_max_rows: 200
  ripestat_timeframe_days: 14
  peeringdb_cache_hours: 24
  firehol_refresh_hours: 24
  firehol_netsets:
    - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
    - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_30d.netset"

dnsbl:
  zones:
    - "zen.spamhaus.org"
    - "bl.spamcop.net"
    - "b.barracudacentral.org"
    - "dnsbl.dronebl.org"

thresholds:
  latency_ms: { good: 40.0, warn: 100.0 }
  jitter_ms: { good: 5.0, warn: 20.0 }
  loss_pct: { good: 0.0, warn: 2.0 }
  bufferbloat_ms: { a: 5.0, b: 30.0, c: 60.0, d: 200.0, e: 400.0 }
  vpn_confidence: { likely: 0.40, confirmed: 0.75 }

output:
  logs_dir: "./logs"
  cache_dir: "./.cache"
  emoji: true

watch:
  interval_seconds: 60
  speedtest_every_n_cycles: 10
  dashboard_refresh_hz: 4
```

- [ ] **Step 6: Create the package stubs**

`src/netcheck/__init__.py`:

```python
__version__ = "0.1.0"
```

`src/netcheck/probes/__init__.py`: empty file.

`src/netcheck/cli.py` (stub, fully replaced in Task 37):

```python
from __future__ import annotations

import typer

from netcheck import __version__

app = typer.Typer(add_completion=False, help="Deep network diagnostics.")


@app.command()
def run() -> None:
    typer.echo(f"netcheck {__version__}")


def main() -> None:
    app()
```

`src/netcheck/__main__.py`:

```python
from netcheck.cli import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 7: Create `tests/conftest.py`**

```python
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
```

Create the empty fixture directories so the tree exists:

```bash
mkdir -p tests/fixtures/api tests/fixtures/reports
mkdir -p tests/fixtures/traceroute/windows tests/fixtures/traceroute/linux tests/fixtures/traceroute/darwin
```

- [ ] **Step 8: Bootstrap the environment with uv and lock**

```bash
uv venv
uv sync --all-extras --group dev
uv export --no-hashes --format requirements-txt -o requirements.txt
```

Expected: `.venv/` created, `uv.lock` written, `requirements.txt` written.

- [ ] **Step 9: Verify the package imports and pytest collects cleanly**

```bash
uv run python -c "import netcheck; print(netcheck.__version__)"
uv run python -m netcheck
uv run pytest -q
```

Expected: `0.1.0` printed twice (once as `netcheck 0.1.0`), and pytest reports `no tests ran` / `collected 0 items` with **exit status 5 and zero collection errors**. A collection *error* here means the src-layout install is wrong — fix before continuing.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml uv.lock requirements.txt LICENSE .env.example config.yaml .gitignore src tests
git commit -m "project scaffold: uv packaging, config.yaml, package skeleton"
```

---

### Task 2: Bilingual README and ARCHITECTURE

**Files:**
- Create: `README.md`, `README.ru.md`, `ARCHITECTURE.md`, `ARCHITECTURE.ru.md`

**Interfaces:**
- Consumes: the module layout and flags from Task 1's `config.yaml` and the spec.
- Produces: documentation contract that Task 41 re-verifies against the final module list.

This task has no business logic and therefore no tests — it is documentation. The repo currently has commits *without* these four files, which violates the public-repo convention; this task closes that gap before any module work.

- [ ] **Step 1: Write `README.md`**

````markdown
# netcheck

[Русский](README.ru.md)

Cross-platform CLI for deep network diagnostics: who your ISP actually is, whether a VPN is really carrying your traffic, where the path degrades, and what your line actually delivers.

```console
$ netcheck --quick
netcheck 0.1.0 · auto mode · Windows

Connection   Wi-Fi 2  ·  192.168.1.34  ·  MTU 1500  ·  gw 192.168.1.1
Egress       203.0.113.44  (AS64500 Example Telecom, Amsterdam NL)
VPN          none          confidence 0.10
Latency      1.1.1.1  12.4 ms avg  ·  jitter 1.9 ms  ·  loss 0%
Verdict      🟢 healthy — no problems found

Report written to logs/report_AS64500_20260808T191200Z.md
                 logs/report_AS64500_20260808T191200Z.json
```

## Install

Requirements:

- Python 3.10 or newer
- Windows, Linux or macOS
- Internet access (netcheck is a network tool; it degrades gracefully but cannot do much offline)
- Optional: the native Ookla `speedtest` binary on `PATH` for the best bandwidth tier
- Optional: `mtr` on `PATH` for the best path data

```bash
git clone https://github.com/<owner>/netcheck
cd netcheck
uv sync
uv run netcheck
```

Without `uv`:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
netcheck
```

No configuration is required. Copy `.env.example` to `.env` only if you have optional API keys.

## What it does

- **Identity** — egress IPv4 *and* IPv6, reverse DNS, ASN, organisation, geo, and whether the address looks residential, mobile, hosting or business. Cross-checked across six independent providers so one rate limit does not blank the answer.
- **VPN / proxy assessment** — a weighted verdict (`none` / `likely` / `confirmed`) built from tunnel interfaces, MTU anomalies, gateway-vs-egress mismatch, Cloudflare WARP flags, provider proxy/hosting flags, PeeringDB network type, timezone-vs-geo mismatch, and DNS resolver ASN mismatch.
- **DNS leak test** — enumerates resolvers *per network adapter*, so it catches the classic case where the tunnel adapter is clean but the Wi-Fi adapter still holds the ISP resolver. Also detects EDNS Client Subnet leakage.
- **BGP intelligence** — upstreams, peers, downstreams, announced prefixes, route stability, IXP presence, and CAIDA ASRank customer-cone size.
- **Reputation** — locally cached FireHOL blocklists (no query leaves your machine), Shodan InternetDB exposure, and optional classic DNSBL zones.
- **Latency & path** — per-host ping statistics with real jitter/loss/mdev, and a traceroute that never needs administrator rights.
- **Bandwidth** — a cascading speedtest (Ookla binary → Cloudflare → fast.com → optional M-Lab NDT7) with separate download and upload bufferbloat grades.

## Handy things

| Flag | What it does |
|---|---|
| `--quick` | ~10 s express run: reference-host pings only, no speedtest |
| `--full` | ~60–120 s: full speedtest and full MTR cycles |
| `--target AS64500` / `--target 1.2.3.4` / `--target example.com` | Investigate a specific network instead of your own connection |
| `--target-host <ip\|domain>` | Add an extra host to the ping and traceroute fan-out |
| `--speedtest-server <id\|url>` | Pin the speedtest to a specific server |
| `--watch` | Continuous monitoring with a live dashboard — for catching intermittent drops |
| `--compare a.json b.json` | Diff two earlier reports: before/after a VPN switch, before/after an ISP call |
| `--dnsbl` | Opt in to classic DNSBL reputation zones |
| `--ndt7` | Opt in to M-Lab NDT7 (publishes your measurement, including your IP, as CC0 open data) |
| `--tcp-trace` | Opt in to a scapy TCP-SYN traceroute through ICMP-filtering middleboxes (needs Npcap or root) |

Every run writes two files into `./logs/`: a Markdown report to read and a JSON dump containing every raw provider response, untruncated. `./logs/` is gitignored — reports contain your external IP, city, coordinates and ISP name.

netcheck never requires administrator or root. Where privileges would give better data, it degrades to an unprivileged method and says so in the report.

## For developers

Stack: Python 3.10+, Typer, Rich, httpx, pydantic-settings, dnspython, psutil, icmplib, ctypes.

```bash
uv sync --all-extras --group dev
uv run pytest -q
uv run netcheck --quick
uv export --no-hashes --format requirements-txt -o requirements.txt   # after dependency changes
```

Architecture, data flow and the reasoning behind each provider choice: [ARCHITECTURE.md](ARCHITECTURE.md).

## Credits

netcheck reads from RIPEstat, CAIDA ASRank, Team Cymru, PeeringDB, Cloudflare, ip-api.com, freeipapi.com, ipinfo.io, ipwho.is, Shodan InternetDB, the FireHOL blocklist project, Netflix fast.com and M-Lab. All of them are used within their free/keyless tiers.

## License

Not yet finalized — see [LICENSE](LICENSE). The choice is between MIT and Polyform Noncommercial; the default reputation sources (Shodan InternetDB, Spamhaus free mirrors) are non-commercial-use-only, which is the crux of the decision.
````

- [ ] **Step 2: Write `README.ru.md`** — a full standalone translation with the same structure

````markdown
# netcheck

[English](README.md)

Кроссплатформенная CLI-утилита для глубокой диагностики сети: кто на самом деле ваш провайдер, действительно ли трафик идёт через VPN, где деградирует маршрут и что реально выдаёт канал.

```console
$ netcheck --quick
netcheck 0.1.0 · авто-режим · Windows

Соединение   Wi-Fi 2  ·  192.168.1.34  ·  MTU 1500  ·  шлюз 192.168.1.1
Внешний IP   203.0.113.44  (AS64500 Example Telecom, Амстердам NL)
VPN          нет           уверенность 0.10
Задержка     1.1.1.1  12.4 мс сред.  ·  джиттер 1.9 мс  ·  потери 0%
Вердикт      🟢 всё в порядке — проблем не найдено

Отчёт записан в logs/report_AS64500_20260808T191200Z.md
                 logs/report_AS64500_20260808T191200Z.json
```

## Установка

Требования:

- Python 3.10 или новее
- Windows, Linux или macOS
- Доступ в интернет (netcheck — сетевой инструмент; без сети он деградирует корректно, но сделает немного)
- Опционально: нативный бинарник Ookla `speedtest` в `PATH` — лучший уровень замера скорости
- Опционально: `mtr` в `PATH` — лучшие данные по маршруту

```bash
git clone https://github.com/<owner>/netcheck
cd netcheck
uv sync
uv run netcheck
```

Без `uv`:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
netcheck
```

Настройка не требуется. Копируйте `.env.example` в `.env` только если у вас есть опциональные API-ключи.

## Что он делает

- **Идентификация** — внешний IPv4 *и* IPv6, обратный DNS, ASN, организация, гео и тип адреса: домашний, мобильный, хостинговый или корпоративный. Проверяется по шести независимым источникам, поэтому один rate-limit не обнуляет результат.
- **Оценка VPN/прокси** — взвешенный вердикт (`none` / `likely` / `confirmed`) из наличия туннельного интерфейса, аномалии MTU, расхождения шлюза и внешнего IP, флагов Cloudflare WARP, флагов proxy/hosting от провайдеров данных, типа сети в PeeringDB, расхождения таймзоны ОС и гео, а также несовпадения ASN DNS-резолвера.
- **Тест утечки DNS** — перечисляет резолверы *по каждому сетевому адаптеру*, поэтому ловит классический случай, когда туннельный адаптер чистый, а на Wi-Fi-адаптере остался резолвер провайдера. Также определяет утечку EDNS Client Subnet.
- **BGP-разведка** — аплинки, пиры, клиенты, анонсируемые префиксы, стабильность маршрутов, присутствие на IX и размер клиентского конуса по CAIDA ASRank.
- **Репутация** — локально кэшируемые списки FireHOL (ни один запрос не покидает машину), экспозиция по Shodan InternetDB и опционально классические зоны DNSBL.
- **Задержки и маршрут** — статистика пингов по каждому хосту с настоящими джиттером/потерями/mdev и трассировка, которой никогда не нужны права администратора.
- **Скорость** — каскадный замер (бинарник Ookla → Cloudflare → fast.com → опционально M-Lab NDT7) с раздельными оценками bufferbloat на приём и передачу.

## Полезное

| Флаг | Что делает |
|---|---|
| `--quick` | Экспресс-прогон ~10 с: только пинги эталонных хостов, без замера скорости |
| `--full` | 60–120 с: полный замер скорости и полный MTR |
| `--target AS64500` / `--target 1.2.3.4` / `--target example.com` | Исследовать конкретную сеть вместо своего подключения |
| `--target-host <ip\|domain>` | Добавить хост в веер пингов и трассировок |
| `--speedtest-server <id\|url>` | Зафиксировать конкретный сервер замера скорости |
| `--watch` | Непрерывный мониторинг с живой панелью — чтобы поймать плавающие обрывы |
| `--compare a.json b.json` | Сравнить два прошлых отчёта: до/после смены VPN, до/после звонка провайдеру |
| `--dnsbl` | Включить проверку по классическим зонам DNSBL |
| `--ndt7` | Включить M-Lab NDT7 (замер публикуется как открытые данные CC0, включая ваш IP) |
| `--tcp-trace` | Включить TCP-SYN-трассировку через scapy сквозь middlebox'ы, режущие ICMP (нужен Npcap или root) |

Каждый прогон пишет в `./logs/` два файла: Markdown-отчёт для чтения и JSON-дамп со всеми сырыми ответами провайдеров без усечения. `./logs/` в gitignore — отчёты содержат ваш внешний IP, город, координаты и название провайдера.

netcheck никогда не требует администратора или root. Там, где привилегии дали бы данные лучше, он деградирует до непривилегированного метода и пишет об этом в отчёте.

## Для разработчиков

Стек: Python 3.10+, Typer, Rich, httpx, pydantic-settings, dnspython, psutil, icmplib, ctypes.

```bash
uv sync --all-extras --group dev
uv run pytest -q
uv run netcheck --quick
uv export --no-hashes --format requirements-txt -o requirements.txt   # после изменения зависимостей
```

Архитектура, потоки данных и обоснование выбора каждого источника: [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md).

## Благодарности

netcheck читает данные из RIPEstat, CAIDA ASRank, Team Cymru, PeeringDB, Cloudflare, ip-api.com, freeipapi.com, ipinfo.io, ipwho.is, Shodan InternetDB, проекта блоклистов FireHOL, Netflix fast.com и M-Lab. Все они используются в рамках бесплатных/безключевых тарифов.

## Лицензия

Пока не выбрана — см. [LICENSE](LICENSE). Выбор между MIT и Polyform Noncommercial; источники репутации по умолчанию (Shodan InternetDB, свободные зеркала Spamhaus) разрешены только для некоммерческого использования — в этом суть решения.
````

- [ ] **Step 3: Write `ARCHITECTURE.md`**

````markdown
# Architecture

[Русский](ARCHITECTURE.ru.md)

netcheck collects network facts from many independent, mostly keyless sources, merges them into typed structures, interprets them with pure functions, and renders two artifacts per run. Collection, interpretation and rendering never mix: every module either gathers data or reasons about already-gathered data, never both.

## Directory layout

```
src/netcheck/
  cli.py          Typer app: flags, phase orchestration, Rich progress. No business logic.
  config.py       pydantic-settings loader. Precedence: env > .env > config.yaml > default.
  models.py       Every shared dataclass, plus to_jsonable() for serialization.
  orchestration.py  run_module(): timing, timeout, exception -> ProbeError classification.
  netinfo.py      Capability detection and local interface/gateway/MTU/resolver facts.
  ip_geo.py       Six-provider identity chain, per-provider normalizers, field-wise merge.
  bgp.py          RIPEstat, CAIDA ASRank, Team Cymru DNS, PeeringDB (disk-cached).
  reputation.py   FireHOL netset cache + prefix lookup, Shodan InternetDB, DNSBL decode.
  stats.py        Pure RTT statistics: loss, min/avg/max, mdev, jitter.
  traceparse.py   Pure text -> TraceHop parsers for Windows, Linux and BSD/macOS output.
  interpret.py    Pure verdict engine: thresholds -> Finding[], VPN scoring, bufferbloat grade.
  speed.py        Cascading speedtest, throughput math, cfL4 header parsing, bufferbloat probe.
  exporter.py     JSON and Markdown rendering, atomic writes into ./logs/.
  compare.py      --compare: diff two saved JSON reports.
  watch.py        --watch: periodic re-run loop with a live Rich dashboard.
  probes/
    latency.py    Ping fan-out and jitter/loss/mdev statistics.
    traceroute.py Cascade: mtr --json -> icmp_win -> icmplib -> system binary text.
    icmp_win.py   ctypes IcmpSendEcho2 / Icmp6SendEcho2 engine (Windows only).
    dns_leak.py   Per-adapter resolver enumeration, echo probes, ECS detection.
```

## Data flow

```
                +-- netinfo (local facts, capabilities)
                |
  cli.py -------+-- ip_geo provider chain  ---> egress IP + ASN   [blocking: everything downstream needs the ASN]
                |
                +-- bgp || reputation || dns_leak        (parallel)
                |
                +-- latency || traceroute fan-out        (parallel, semaphore-bounded)
                |
                +-- speed                                 (exclusive phase lock)
                |
                +-- interpret  ---> Finding[] + overall verdict
                |
                +-- exporter   ---> logs/report_<ASN>_<ts>.md + .json
```

Two hard concurrency constraints:

1. **Measurement isolation.** The speedtest never overlaps traceroute, ping or API calls — it holds an exclusive phase lock. The single intentional exception is the bufferbloat probe, which overlaps saturation by design, inside `speed.py`.
2. **Bounded traceroute fan-out.** Parallel traceroutes to different targets share early hops and inflate each other's latency, so concurrent traces are capped by a semaphore (`probing.trace_concurrency`, default 2).

## Key decisions

**Failure is a value, not control flow.** Every module call goes through `run_module()`, which times it, enforces a per-module timeout, catches everything except `CancelledError`, and returns a `ModuleResult` with `status` in `ok | partial | failed | skipped`. `asyncio.gather(..., return_exceptions=True)` is a second net at the orchestration layer. No single provider outage can abort a run, and both output formats show every failure explicitly — a report missing its speed section must never look identical to a report where speed was fine.

**Never require elevation.** Capability detection is attempt-based, never OS-assumption-based: try unprivileged datagram ICMP, then raw ICMP, then (on Windows) the `IcmpSendEcho2` API, then fall back to TCP-connect timing and the Cloudflare `Server-Timing: cfL4` header. Worst case, the tool still produces a full report and states the degradation once, plainly, with the one-line remedy.

**Windows traceroute uses the Win32 ICMP API, not `tracert.exe` text.** `IcmpSendEcho2` from `Iphlpapi.dll` is the same unprivileged API `tracert.exe` uses internally. Driving it through `ctypes` gives per-hop RTT, TTL-expiry detection and real timeout handling with no Administrator, no Npcap and no third-party dependency — strictly better than parsing a localized three-probe text table.

**Text parsing is a last resort, and parses by line shape.** When the system binary is the only option, `traceparse.py` matches on structure (leading hop integer, RTT tokens, IP regex) and never on header or footer wording, because Windows `tracert` output is code-page dependent — cp866 on Russian Windows, not UTF-8. BSD/macOS additionally emits multiple IPs per hop and `!H`/`!N`/`!X` annotations that Linux does not, so the three parsers are genuinely separate.

**Latency never parses `ping` text.** That would mean three more locale-dependent parsers for no benefit. Every `PingResult` is tagged with the method used, because TCP "loss" (connection failure rate) and ICMP loss are different metrics and must never be silently conflated.

**Reputation defaults to sources that do not learn what you are checking.** FireHOL netsets are downloaded once, cached, and matched locally — no runtime query, no rate limit, no disclosure. Shodan InternetDB tells a home user something actionable (an exposed router, a forgotten port-forward) far more often than a mail blocklist does. Classic DNSBLs are opt-in behind `--dnsbl`.

**DNSBL responses in `127.255.255.0/24` are errors, not listings.** Spamhaus returns `127.255.255.254` for "you queried through a public resolver" — which is the case for anyone on 1.1.1.1 or 8.8.8.8 — and `127.255.255.255` for "rate limited". A naive "any `127.x.x.x` means listed" implementation red-flags most users. Both are surfaced as *result unavailable*, never as a finding.

**Bulk RIPEstat endpoints are always bounded.** `routing-history` and friends return 10 MB+ payloads for large ISPs, so every such call carries `max_rows` and a timeframe from `config.yaml`.

**PeeringDB is cached to disk.** Anonymous limits are 20 requests/minute with large responses throttled to one per hour, so a response is never re-fetched within a run and persists in `.cache/` between runs for `providers.peeringdb_cache_hours`.

**The JSON dump carries a `raw` section.** Every provider response is stored verbatim under its source key. The typed layer above it necessarily drops fields; `raw` is what actually satisfies "100% of collected data, no truncation".

## Storage

- `./logs/report_<ASN>_<YYYYMMDDTHHMMSSZ>.{md,json}` — one pair per run. Compact ISO timestamps because Windows forbids `:` in filenames. Falls back to `report_unknown_…` when the ASN lookup fails entirely. Written temp-file-plus-`os.replace()`, always atomic. Gitignored: reports contain the external IP, city, coordinates and ISP name.
- `./.cache/firehol/*.netset` — downloaded blocklists, refreshed per `providers.firehol_refresh_hours`.
- `./.cache/peeringdb/*.json` — PeeringDB responses, valid for `providers.peeringdb_cache_hours`.
- `./config.yaml` — all non-secret settings. `./.env` — the three optional API keys and nothing else.

## Configuration

`config.py` builds a pydantic-settings `Settings` object whose sources are ordered **init > environment > `.env` > `config.yaml` > field default**. The three API keys are `SecretStr | None = None` at the top level: a diagnostics tool must run with zero configuration, so a missing key downgrades the enrichment that needs it to `skipped` with a warning and never fails the run.

## Tests

`uv run pytest -q`. Roughly 120 tests covering the parsers, normalizers, verdict engine, DNSBL decoding, throughput math, ping statistics, serialization and the report diff. Glue is deliberately untested: live HTTP, real ICMP, Typer wiring, `psutil`/`ctypes` calls and the `--watch` timing loop. Traceroute fixtures live in `tests/fixtures/traceroute/{windows,linux,darwin}/` and include a cp866-encoded Russian Windows sample, because that encoding is exactly what breaks naive parsers.
````

- [ ] **Step 4: Write `ARCHITECTURE.ru.md`** — full standalone translation

````markdown
# Архитектура

[English](ARCHITECTURE.md)

netcheck собирает сетевые факты из множества независимых, в основном безключевых источников, сводит их в типизированные структуры, интерпретирует чистыми функциями и на каждый прогон отдаёт два артефакта. Сбор, интерпретация и рендер никогда не смешиваются: модуль либо собирает данные, либо рассуждает об уже собранных — но не одновременно.

## Структура каталогов

```
src/netcheck/
  cli.py          Typer-приложение: флаги, порядок фаз, прогресс Rich. Без бизнес-логики.
  config.py       Загрузчик pydantic-settings. Приоритет: env > .env > config.yaml > default.
  models.py       Все общие датаклассы плюс to_jsonable() для сериализации.
  orchestration.py  run_module(): тайминг, таймаут, классификация исключений в ProbeError.
  netinfo.py      Определение возможностей и локальные факты: интерфейс, шлюз, MTU, резолверы.
  ip_geo.py       Цепочка из шести провайдеров, нормализаторы, пополевое слияние.
  bgp.py          RIPEstat, CAIDA ASRank, Team Cymru через DNS, PeeringDB (кэш на диске).
  reputation.py   Кэш netset'ов FireHOL и локальный поиск, Shodan InternetDB, декодер DNSBL.
  stats.py        Чистая статистика RTT: потери, min/avg/max, mdev, джиттер.
  traceparse.py   Чистые парсеры текста в TraceHop для Windows, Linux и BSD/macOS.
  interpret.py    Чистый движок вердиктов: пороги -> Finding[], скоринг VPN, оценка bufferbloat.
  speed.py        Каскадный замер скорости, математика пропускной способности, разбор cfL4, bufferbloat.
  exporter.py     Рендер JSON и Markdown, атомарная запись в ./logs/.
  compare.py      --compare: сравнение двух сохранённых JSON-отчётов.
  watch.py        --watch: цикл периодических прогонов с живой панелью Rich.
  probes/
    latency.py    Веер пингов и статистика джиттера/потерь/mdev.
    traceroute.py Каскад: mtr --json -> icmp_win -> icmplib -> системный бинарник.
    icmp_win.py   Движок ctypes IcmpSendEcho2 / Icmp6SendEcho2 (только Windows).
    dns_leak.py   Перечисление резолверов по адаптерам, echo-пробы, детект ECS.
```

## Поток данных

```
                +-- netinfo (локальные факты, возможности)
                |
  cli.py -------+-- цепочка ip_geo  ---> внешний IP + ASN   [блокирующая фаза: всё дальше зависит от ASN]
                |
                +-- bgp || reputation || dns_leak         (параллельно)
                |
                +-- latency || веер traceroute            (параллельно, ограничено семафором)
                |
                +-- speed                                  (эксклюзивная фаза)
                |
                +-- interpret  ---> Finding[] + общий вердикт
                |
                +-- exporter   ---> logs/report_<ASN>_<ts>.md + .json
```

Два жёстких ограничения по конкурентности:

1. **Изоляция измерений.** Замер скорости никогда не пересекается с трассировкой, пингами и запросами к API — он держит эксклюзивную блокировку фазы. Единственное намеренное исключение — проба bufferbloat, которая по замыслу работает во время насыщения канала, внутри `speed.py`.
2. **Ограниченный веер трассировок.** Параллельные трассировки к разным целям делят первые хопы и завышают задержки друг друга, поэтому число одновременных трассировок ограничено семафором (`probing.trace_concurrency`, по умолчанию 2).

## Ключевые решения

**Отказ — это значение, а не поток управления.** Каждый вызов модуля проходит через `run_module()`: он замеряет время, применяет таймаут на модуль, перехватывает всё кроме `CancelledError` и возвращает `ModuleResult` со статусом `ok | partial | failed | skipped`. `asyncio.gather(..., return_exceptions=True)` — вторая страховка на уровне оркестрации. Ни один сбой провайдера не может прервать прогон, и оба формата вывода показывают каждый сбой явно: отчёт без раздела скорости не должен выглядеть так же, как отчёт, где со скоростью всё было хорошо.

**Никогда не требовать повышения прав.** Определение возможностей построено на попытках, а не на предположениях об ОС: сначала непривилегированный datagram ICMP, затем raw ICMP, затем (на Windows) API `IcmpSendEcho2`, затем откат на тайминг TCP-connect и заголовок Cloudflare `Server-Timing: cfL4`. В худшем случае инструмент всё равно выдаёт полный отчёт и один раз, простыми словами, сообщает о деградации и способе её устранить.

**Трассировка на Windows использует Win32 ICMP API, а не текст `tracert.exe`.** `IcmpSendEcho2` из `Iphlpapi.dll` — тот же непривилегированный API, который `tracert.exe` использует внутри. Через `ctypes` он даёт RTT по хопам, определение истёкшего TTL и корректные таймауты без администратора, Npcap и сторонних зависимостей — строго лучше, чем разбор локализованной таблицы из трёх проб.

**Разбор текста — крайняя мера, и он опирается на форму строки.** Когда системный бинарник — единственный вариант, `traceparse.py` смотрит на структуру (ведущее целое хопа, токены RTT, регулярка IP) и никогда на слова в заголовке или подвале: вывод `tracert` зависит от кодовой страницы — cp866 на русской Windows, а не UTF-8. BSD/macOS вдобавок выдаёт несколько IP на хоп и аннотации `!H`/`!N`/`!X`, которых нет в Linux, поэтому три парсера действительно разные.

**Замер задержек не разбирает текст `ping`.** Это означало бы ещё три locale-зависимых парсера без всякой пользы. Каждый `PingResult` помечен использованным методом, потому что «потери» TCP (доля неудачных подключений) и потери ICMP — разные метрики, и молча смешивать их в отчёте нельзя.

**Репутация по умолчанию опирается на источники, которые не узнают, что вы проверяете.** Netset'ы FireHOL скачиваются один раз, кэшируются и сопоставляются локально — ни запроса наружу, ни лимитов, ни раскрытия. Shodan InternetDB для домашнего пользователя гораздо чаще говорит что-то полезное (открытый роутер, забытый проброс порта), чем почтовый блоклист. Классические DNSBL включаются явно флагом `--dnsbl`.

**Ответы DNSBL в диапазоне `127.255.255.0/24` — это ошибки, а не листинг.** Spamhaus возвращает `127.255.255.254` на «вы спросили через публичный резолвер» — а это все, кто сидит на 1.1.1.1 или 8.8.8.8 — и `127.255.255.255` на «превышен лимит». Наивная реализация «любой `127.x.x.x` значит в списке» помечает красным большинство пользователей. Оба случая подаются как *результат недоступен*, но никогда как находка.

**Массовые эндпоинты RIPEstat всегда ограничены.** `routing-history` и подобные на крупных провайдерах возвращают 10 МБ+, поэтому каждый такой вызов несёт `max_rows` и временное окно из `config.yaml`.

**PeeringDB кэшируется на диск.** Анонимные лимиты — 20 запросов в минуту, а крупные ответы душатся до одного в час, поэтому ответ не запрашивается повторно внутри прогона и сохраняется в `.cache/` между прогонами на `providers.peeringdb_cache_hours`.

**В JSON-дампе есть раздел `raw`.** Каждый ответ провайдера сохраняется дословно под ключом источника. Типизированный слой над ним неизбежно теряет поля; именно `raw` действительно выполняет требование «100% собранных данных без усечения».

## Хранение

- `./logs/report_<ASN>_<YYYYMMDDTHHMMSSZ>.{md,json}` — пара файлов на прогон. Компактный ISO-таймстамп, потому что Windows запрещает `:` в именах файлов. При полном провале определения ASN — `report_unknown_…`. Запись через временный файл и `os.replace()`, всегда атомарно. В gitignore: отчёты содержат внешний IP, город, координаты и название провайдера.
- `./.cache/firehol/*.netset` — скачанные блоклисты, обновляются по `providers.firehol_refresh_hours`.
- `./.cache/peeringdb/*.json` — ответы PeeringDB, действительны `providers.peeringdb_cache_hours`.
- `./config.yaml` — все несекретные настройки. `./.env` — три опциональных API-ключа и ничего больше.

## Конфигурация

`config.py` собирает объект `Settings` на pydantic-settings, источники которого упорядочены **init > переменные окружения > `.env` > `config.yaml` > значение по умолчанию**. Три API-ключа объявлены как `SecretStr | None = None` на верхнем уровне: диагностический инструмент обязан работать с нулевой настройкой, поэтому отсутствие ключа переводит зависящее от него обогащение в `skipped` с предупреждением и никогда не роняет прогон.

## Тесты

`uv run pytest -q`. Около 120 тестов: парсеры, нормализаторы, движок вердиктов, декодирование DNSBL, математика пропускной способности, статистика пингов, сериализация и сравнение отчётов. Клей намеренно не тестируется: живой HTTP, настоящий ICMP, обвязка Typer, вызовы `psutil`/`ctypes` и цикл `--watch`. Фикстуры трассировок лежат в `tests/fixtures/traceroute/{windows,linux,darwin}/` и включают образец русской Windows в cp866 — именно эта кодировка ломает наивные парсеры.
````

- [ ] **Step 5: Verify the cross-links exist**

```bash
head -3 README.md README.ru.md ARCHITECTURE.md ARCHITECTURE.ru.md
```

Expected: `README.md` line 3 is `[Русский](README.ru.md)`, `README.ru.md` line 3 is `[English](README.md)`, and the same pattern for the two ARCHITECTURE files.

- [ ] **Step 6: Commit**

```bash
git add README.md README.ru.md ARCHITECTURE.md ARCHITECTURE.ru.md
git commit -m "bilingual readme and architecture docs"
```

---
## Phase 1 — Foundation

### Task 3: Core envelopes in `models.py`

**Files:**
- Create: `src/netcheck/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ERROR_KINDS: tuple[str, ...]`, `STATUSES: tuple[str, ...]`, `SEVERITIES: tuple[str, ...]`
  - `ProbeError(source: str, kind: str, message: str, retryable: bool = False)` — raises `ValueError` on an unknown `kind`
  - `ModuleResult(name: str, status: str, data: Any | None = None, errors: list[ProbeError] = [], warnings: list[str] = [], started_at: str = "", duration_ms: int = 0)`
  - `Finding(id: str, severity: str, title: str, detail: str, metric: str | None, value: float | str | None, threshold: float | str | None, advice: str | None)`
  - `Signal(name: str, observed: bool, weight: float, direction: str, note: str = "")`
  - `to_jsonable(obj: Any) -> Any`

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:

```python
from __future__ import annotations

import json

import pytest

from netcheck.models import Finding, ModuleResult, ProbeError, Signal, to_jsonable


def test_probe_error_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown ProbeError kind"):
        ProbeError(source="ip-api", kind="exploded", message="boom")


@pytest.mark.parametrize(
    "kind",
    [
        "timeout",
        "http_error",
        "rate_limited",
        "blocked",
        "parse_error",
        "unavailable",
        "no_privilege",
        "not_applicable",
    ],
)
def test_probe_error_accepts_documented_kinds(kind):
    assert ProbeError(source="s", kind=kind, message="m").kind == kind


def test_module_result_rejects_unknown_status():
    with pytest.raises(ValueError, match="unknown ModuleResult status"):
        ModuleResult(name="bgp", status="borked")


def test_module_result_serializes_to_strict_json():
    result = ModuleResult(
        name="reputation",
        status="partial",
        data={"firehol_hits": ["firehol_level1"]},
        errors=[ProbeError(source="internetdb", kind="timeout", message="8s", retryable=True)],
        warnings=["abuseipdb key missing"],
        started_at="2026-08-08T19:12:00Z",
        duration_ms=1234,
    )
    text = json.dumps(to_jsonable(result), allow_nan=False)
    back = json.loads(text)
    assert back["name"] == "reputation"
    assert back["status"] == "partial"
    assert back["data"]["firehol_hits"] == ["firehol_level1"]
    assert back["errors"][0] == {
        "source": "internetdb",
        "kind": "timeout",
        "message": "8s",
        "retryable": True,
    }
    assert back["warnings"] == ["abuseipdb key missing"]
    assert back["duration_ms"] == 1234


def test_to_jsonable_coerces_non_finite_numbers_to_null():
    payload = {"a": float("inf"), "b": float("-inf"), "c": float("nan"), "d": 1.5}
    out = to_jsonable(payload)
    assert out == {"a": None, "b": None, "c": None, "d": 1.5}
    json.dumps(out, allow_nan=False)


def test_to_jsonable_handles_nested_dataclasses_and_sets():
    finding = Finding(
        id="latency.high",
        severity="warn",
        title="Latency above target",
        detail="avg 130 ms to 1.1.1.1",
        metric="avg_ms",
        value=130.0,
        threshold=100.0,
        advice="Check for a saturated uplink.",
    )
    signal = Signal(name="tunnel_iface", observed=True, weight=0.35, direction="vpn", note="wg0")
    out = to_jsonable({"findings": [finding], "signals": (signal,), "tags": {"a"}})
    assert out["findings"][0]["severity"] == "warn"
    assert out["signals"][0]["weight"] == 0.35
    assert out["tags"] == ["a"]
    json.dumps(out, allow_nan=False)


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError, match="unknown Finding severity"):
        Finding(
            id="x",
            severity="apocalyptic",
            title="t",
            detail="d",
            metric=None,
            value=None,
            threshold=None,
            advice=None,
        )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_models.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.models'`.

- [ ] **Step 3: Implement `src/netcheck/models.py` (core envelopes only)**

```python
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
        # allow_nan=False would raise on inf/NaN, which zero-duration timing math
        # can produce exactly on the failure paths the report most needs to show.
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_models.py -q`
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/models.py tests/test_models.py
git commit -m "models: ModuleResult, ProbeError, Finding, Signal envelopes"
```

---

### Task 4: Domain shapes in `models.py`

**Files:**
- Modify: `src/netcheck/models.py` (append)
- Test: `tests/test_models.py` (append)

**Interfaces:**
- Consumes: Task 3's `to_jsonable`.
- Produces (every field name below is load-bearing — later tasks reference them exactly):
  - `Capabilities`, `LocalNet`, `IpGeo`, `CfTrace`, `VpnAssessment`, `DnsLeak`, `AdapterLeakResult`
  - `BgpEvent`, `IxpPresence`, `BgpIntel`
  - `InternetDbResult`, `DnsblHit`, `Reputation`
  - `PingResult`, `TraceHop`, `TraceResult`
  - `TierAttempt`, `CfL4Stats`, `SpeedResult`

- [ ] **Step 1: Write the failing test (append to `tests/test_models.py`)**

```python
from netcheck.models import (
    AdapterLeakResult,
    BgpEvent,
    BgpIntel,
    Capabilities,
    CfL4Stats,
    CfTrace,
    DnsLeak,
    DnsblHit,
    InternetDbResult,
    IpGeo,
    IxpPresence,
    LocalNet,
    PingResult,
    Reputation,
    SpeedResult,
    TierAttempt,
    TraceHop,
    TraceResult,
    VpnAssessment,
)


def test_every_domain_shape_defaults_to_constructible_with_no_arguments():
    for cls in (
        Capabilities,
        LocalNet,
        IpGeo,
        CfTrace,
        VpnAssessment,
        DnsLeak,
        BgpIntel,
        Reputation,
        SpeedResult,
        TraceResult,
    ):
        instance = cls()
        json.dumps(to_jsonable(instance), allow_nan=False)


def test_ping_result_round_trips_through_json():
    ping = PingResult(
        label="cloudflare-dns",
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_win",
        sent=20,
        received=20,
        loss_pct=0.0,
        min_ms=11.0,
        avg_ms=12.4,
        max_ms=15.1,
        mdev_ms=0.9,
        jitter_ms=1.9,
        samples=[11.0, 12.0, None, 15.1],
    )
    out = json.loads(json.dumps(to_jsonable(ping), allow_nan=False))
    assert out["method"] == "icmp_win"
    assert out["samples"][2] is None


def test_trace_result_nests_hops():
    trace = TraceResult(
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        backend="icmp_win",
        hops=[TraceHop(ttl=1, ip="192.168.1.1", probes=[1.2, 1.1, None], annotations=["!H"])],
        cycles=1,
        completed=True,
    )
    out = to_jsonable(trace)
    assert out["hops"][0]["ttl"] == 1
    assert out["hops"][0]["annotations"] == ["!H"]
    assert out["backend"] == "icmp_win"


def test_reputation_composes_optional_sub_results():
    rep = Reputation(
        internetdb=InternetDbResult(ip="203.0.113.44", ports=[80, 443], tags=["cdn"]),
        firehol_hits=["firehol_level1"],
        dnsbl_hits=[DnsblHit(zone="zen.spamhaus.org", codes=["127.0.0.2"], meaning="listed")],
        dnsbl_query_blocked=False,
        captcha_risk="medium",
        rationale="Listed on one blocklist.",
    )
    out = to_jsonable(rep)
    assert out["internetdb"]["ports"] == [80, 443]
    assert out["dnsbl_hits"][0]["zone"] == "zen.spamhaus.org"


def test_bgp_intel_nests_events_and_ixps():
    bgp = BgpIntel(
        asn="AS64500",
        holder="Example Telecom",
        flaps=[BgpEvent(timestamp="2026-08-01T00:00:00Z", type="A", prefix="203.0.113.0/24")],
        ixps=[IxpPresence(name="AMS-IX", city="Amsterdam", country="NL", speed_mbps=100000)],
        stability="stable",
    )
    out = to_jsonable(bgp)
    assert out["flaps"][0]["prefix"] == "203.0.113.0/24"
    assert out["ixps"][0]["speed_mbps"] == 100000


def test_speed_result_carries_tier_attempts_and_cfl4():
    speed = SpeedResult(
        method="cloudflare",
        tier_attempts=[
            TierAttempt(tier="ookla_bin", ok=False, reason="binary not on PATH"),
            TierAttempt(tier="cloudflare", ok=True, reason=None),
        ],
        download_mbps=284.3,
        upload_mbps=41.7,
        cfL4_stats=CfL4Stats(rtt_ms=12.0, min_rtt_ms=11.0, rtt_var_ms=1.5, delivery_rate_bps=35000000, cwnd=42, unsent_bytes=0, recv_bytes=1048576),
    )
    out = to_jsonable(speed)
    assert out["tier_attempts"][0]["ok"] is False
    assert out["cfL4_stats"]["rtt_ms"] == 12.0


def test_adapter_leak_result_and_dns_leak_compose():
    leak = DnsLeak(
        per_adapter=[
            AdapterLeakResult(
                adapter="Wi-Fi",
                configured_resolvers=["192.168.1.1"],
                echoed_ip="203.0.113.9",
                echoed_asn="AS64501",
                matches_egress_asn=False,
            )
        ],
        ecs_leaked=True,
        note="ISP resolver still active on Wi-Fi adapter.",
    )
    out = to_jsonable(leak)
    assert out["per_adapter"][0]["matches_egress_asn"] is False
    assert out["ecs_leaked"] is True


def test_ip_geo_and_vpn_assessment_defaults_are_json_safe():
    geo = IpGeo(ip="203.0.113.44", ip_version=4, asn="AS64500", sources={"asn": "ip-api"})
    vpn = VpnAssessment(verdict="likely", confidence=0.55, signals=[Signal("warp", True, 0.5, "vpn")])
    out = to_jsonable({"geo": geo, "vpn": vpn})
    assert out["geo"]["ip_type"] == "unknown"
    assert out["vpn"]["signals"][0]["name"] == "warp"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_models.py -q`
Expected: FAIL — `ImportError: cannot import name 'Capabilities' from 'netcheck.models'`.

- [ ] **Step 3: Append the domain shapes to `src/netcheck/models.py`**

```python
@dataclass
class Capabilities:
    os_name: str = ""
    is_elevated: bool = False
    icmp_dgram: bool = False
    icmp_raw: bool = False
    icmp_win_api: bool = False
    mtr_binary: str | None = None
    traceroute_binary: str | None = None
    chosen_latency_backend: str = "none"
    chosen_trace_backend: str = "none"
    notes: list[str] = field(default_factory=list)


@dataclass
class LocalNet:
    iface_name: str | None = None
    local_ipv4: str | None = None
    local_ipv6: str | None = None
    iface_mtu: int | None = None
    default_gateway_v4: str | None = None
    default_gateway_v6: str | None = None
    dns_servers_per_adapter: dict[str, list[str]] = field(default_factory=dict)
    is_dual_stack: bool = False


@dataclass
class IpGeo:
    ip: str | None = None
    ip_version: int | None = None
    reverse_dns: str | None = None
    asn: str | None = None
    as_name: str | None = None
    org: str | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    ip_type: str = "unknown"
    sources: dict[str, str] = field(default_factory=dict)


@dataclass
class CfTrace:
    ip: str | None = None
    colo: str | None = None
    loc: str | None = None
    warp: str | None = None
    gateway: str | None = None
    rbi: str | None = None
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class AdapterLeakResult:
    adapter: str
    configured_resolvers: list[str] = field(default_factory=list)
    echoed_ip: str | None = None
    echoed_asn: str | None = None
    matches_egress_asn: bool | None = None


@dataclass
class DnsLeak:
    per_adapter: list[AdapterLeakResult] = field(default_factory=list)
    ecs_leaked: bool = False
    note: str = ""


@dataclass
class VpnAssessment:
    verdict: str = "none"
    confidence: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    tunnel_iface: str | None = None
    dns_leak: DnsLeak | None = None


@dataclass
class BgpEvent:
    timestamp: str
    type: str
    prefix: str | None = None
    path: list[int] = field(default_factory=list)


@dataclass
class IxpPresence:
    name: str
    city: str | None = None
    country: str | None = None
    speed_mbps: int | None = None


@dataclass
class BgpIntel:
    asn: str | None = None
    holder: str | None = None
    registry: str | None = None
    allocated_at: str | None = None
    upstreams: list[str] = field(default_factory=list)
    peers: list[str] = field(default_factory=list)
    downstreams: list[str] = field(default_factory=list)
    announced_prefixes: list[str] = field(default_factory=list)
    prefix_count_v4: int = 0
    prefix_count_v6: int = 0
    flaps: list[BgpEvent] = field(default_factory=list)
    stability: str = "unknown"
    ixps: list[IxpPresence] = field(default_factory=list)
    pdb_info_type: str | None = None
    pdb_traffic: str | None = None
    asrank: int | None = None
    cone_asns: int | None = None
    cone_prefixes: int | None = None


@dataclass
class InternetDbResult:
    ip: str | None = None
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)


@dataclass
class DnsblHit:
    zone: str
    codes: list[str] = field(default_factory=list)
    meaning: str = "listed"


@dataclass
class Reputation:
    internetdb: InternetDbResult | None = None
    firehol_hits: list[str] = field(default_factory=list)
    dnsbl_hits: list[DnsblHit] | None = None
    dnsbl_query_blocked: bool = False
    abuseipdb_score: int | None = None
    abuseipdb_reports: int | None = None
    captcha_risk: str = "low"
    rationale: str = ""


@dataclass
class PingResult:
    label: str
    host: str
    resolved_ip: str | None = None
    method: str = "none"
    sent: int = 0
    received: int = 0
    loss_pct: float = 0.0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    mdev_ms: float | None = None
    jitter_ms: float | None = None
    samples: list[float | None] = field(default_factory=list)


@dataclass
class TraceHop:
    ttl: int
    ip: str | None = None
    reverse_dns: str | None = None
    asn: str | None = None
    as_name: str | None = None
    probes: list[float | None] = field(default_factory=list)
    loss_pct: float = 0.0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None
    annotations: list[str] = field(default_factory=list)


@dataclass
class TraceResult:
    target: str | None = None
    resolved_ip: str | None = None
    backend: str = "none"
    hops: list[TraceHop] = field(default_factory=list)
    cycles: int = 0
    completed: bool = False
    max_hops_reached: bool = False


@dataclass
class TierAttempt:
    tier: str
    ok: bool
    reason: str | None = None
    duration_ms: int = 0


@dataclass
class CfL4Stats:
    rtt_ms: float | None = None
    min_rtt_ms: float | None = None
    rtt_var_ms: float | None = None
    delivery_rate_bps: int | None = None
    cwnd: int | None = None
    unsent_bytes: int | None = None
    recv_bytes: int | None = None


@dataclass
class SpeedResult:
    method: str = "none"
    tier_attempts: list[TierAttempt] = field(default_factory=list)
    download_mbps: float | None = None
    upload_mbps: float | None = None
    server: str | None = None
    idle_rtt_ms: float | None = None
    loaded_rtt_down_ms: float | None = None
    loaded_rtt_up_ms: float | None = None
    bufferbloat_down_ms: float | None = None
    bufferbloat_up_ms: float | None = None
    bufferbloat_grade: str | None = None
    cfL4_stats: CfL4Stats | None = None
    netflix_oca_onnet: bool | None = None
```

Note the field name `cfL4_stats` keeps the spec's exact casing (§4) — it appears verbatim in the JSON output, so do not "fix" it to `cfl4_stats`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_models.py -q`
Expected: PASS, 22 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/models.py tests/test_models.py
git commit -m "models: domain shapes for geo, bgp, reputation, probes, speed"
```

---

### Task 5: `config.py` — pydantic-settings loader

**Files:**
- Create: `src/netcheck/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `config.yaml` from Task 1.
- Produces:
  - `Settings` (pydantic-settings `BaseSettings`) with nested models `Timeouts`, `Probing`, `HostSpec`, `Speedtest`, `Providers`, `Dnsbl`, `Band`, `BufferbloatBands`, `VpnBands`, `Thresholds`, `Output`, `Watch`
  - Top-level secret fields `ipinfo_token`, `peeringdb_api_key`, `abuseipdb_api_key`, each `SecretStr | None = None`
  - `load_settings(config_path: Path | None = None, env_file: Path | None = None) -> Settings`

- [ ] **Step 1: Write the failing test**

`tests/test_config.py`:

```python
from __future__ import annotations

import textwrap

import pytest

from netcheck.config import load_settings


@pytest.fixture()
def yaml_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        textwrap.dedent(
            """
            timeouts:
              http_seconds: 3.5
            probing:
              ping_count: 7
              reference_hosts:
                - { label: "yaml-host", host: "9.9.9.9" }
            output:
              logs_dir: "./yaml-logs"
              emoji: false
            thresholds:
              latency_ms: { good: 11.0, warn: 22.0 }
            """
        ).strip(),
        encoding="utf-8",
    )
    return path


def test_defaults_apply_when_yaml_omits_a_field(yaml_file, tmp_path):
    s = load_settings(config_path=yaml_file, env_file=tmp_path / "missing.env")
    assert s.probing.max_hops == 30
    assert s.timeouts.module_seconds == 30.0


def test_yaml_overrides_defaults(yaml_file, tmp_path):
    s = load_settings(config_path=yaml_file, env_file=tmp_path / "missing.env")
    assert s.timeouts.http_seconds == 3.5
    assert s.probing.ping_count == 7
    assert s.output.emoji is False
    assert s.thresholds.latency_ms.warn == 22.0
    assert s.probing.reference_hosts[0].host == "9.9.9.9"


def test_dotenv_overrides_yaml(yaml_file, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("NETCHECK_PROBING__PING_COUNT=13\n", encoding="utf-8")
    s = load_settings(config_path=yaml_file, env_file=env_file)
    assert s.probing.ping_count == 13


def test_environment_overrides_dotenv(yaml_file, tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NETCHECK_PROBING__PING_COUNT=13\n", encoding="utf-8")
    monkeypatch.setenv("NETCHECK_PROBING__PING_COUNT", "99")
    s = load_settings(config_path=yaml_file, env_file=env_file)
    assert s.probing.ping_count == 99


def test_secrets_default_to_none_so_the_tool_runs_unconfigured(tmp_path):
    s = load_settings(config_path=tmp_path / "absent.yaml", env_file=tmp_path / "absent.env")
    assert s.ipinfo_token is None
    assert s.peeringdb_api_key is None
    assert s.abuseipdb_api_key is None


def test_secrets_load_from_dotenv_without_the_nested_prefix(tmp_path, monkeypatch):
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("IPINFO_TOKEN=abc123\n", encoding="utf-8")
    s = load_settings(config_path=tmp_path / "absent.yaml", env_file=env_file)
    assert s.ipinfo_token is not None
    assert s.ipinfo_token.get_secret_value() == "abc123"
    assert "abc123" not in repr(s)


def test_missing_yaml_is_not_an_error(tmp_path):
    s = load_settings(config_path=tmp_path / "nope.yaml", env_file=tmp_path / "nope.env")
    assert s.probing.ping_count == 20
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_config.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.config'`.

- [ ] **Step 3: Implement `src/netcheck/config.py`**

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

DEFAULT_CONFIG_PATH = Path("config.yaml")
DEFAULT_ENV_PATH = Path(".env")


class Timeouts(BaseModel):
    http_seconds: float = 8.0
    module_seconds: float = 30.0
    speedtest_seconds: float = 90.0
    dns_seconds: float = 4.0
    subprocess_seconds: float = 60.0


class HostSpec(BaseModel):
    label: str
    host: str


class Probing(BaseModel):
    reference_hosts: list[HostSpec] = Field(
        default_factory=lambda: [
            HostSpec(label="cloudflare-dns", host="1.1.1.1"),
            HostSpec(label="google-dns", host="8.8.8.8"),
            HostSpec(label="quad9-dns", host="9.9.9.9"),
        ]
    )
    service_hosts: list[HostSpec] = Field(
        default_factory=lambda: [
            HostSpec(label="cloudflare", host="cloudflare.com"),
            HostSpec(label="google", host="google.com"),
            HostSpec(label="github", host="github.com"),
        ]
    )
    ping_count: int = 20
    quick_ping_count: int = 5
    ping_interval_seconds: float = 0.25
    ping_timeout_seconds: float = 2.0
    mtr_cycles: int = 10
    quick_mtr_cycles: int = 1
    max_hops: int = 30
    trace_concurrency: int = 2


class Speedtest(BaseModel):
    enabled_tiers: list[str] = Field(default_factory=lambda: ["ookla_bin", "cloudflare", "fastcom"])
    download_sizes_bytes: list[int] = Field(default_factory=lambda: [1_000_000, 10_000_000, 25_000_000])
    upload_sizes_bytes: list[int] = Field(default_factory=lambda: [1_000_000, 5_000_000])
    cloudflare_base_url: str = "https://speed.cloudflare.com"
    fastcom_api_url: str = "https://api.fast.com/netflix/speedtest/v2"
    ndt7_locate_url: str = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
    bufferbloat_probe_interval_seconds: float = 0.2


class Providers(BaseModel):
    cf_trace_url: str = "https://www.cloudflare.com/cdn-cgi/trace"
    ip_api_url: str = "http://ip-api.com/json/"
    freeipapi_url: str = "https://freeipapi.com/api/json/"
    ipinfo_url: str = "https://ipinfo.io/"
    ipwhois_url: str = "https://ipwho.is/"
    ripestat_base_url: str = "https://stat.ripe.net/data"
    asrank_url: str = "https://api.asrank.caida.org/v2/graphql"
    peeringdb_base_url: str = "https://www.peeringdb.com/api"
    internetdb_url: str = "https://internetdb.shodan.io/"
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    cymru_origin_zone: str = "origin.asn.cymru.com"
    cymru_asn_zone: str = "asn.cymru.com"
    ripestat_max_rows: int = 200
    ripestat_timeframe_days: int = 14
    peeringdb_cache_hours: int = 24
    firehol_refresh_hours: int = 24
    firehol_netsets: list[str] = Field(default_factory=list)


class Dnsbl(BaseModel):
    zones: list[str] = Field(
        default_factory=lambda: [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "b.barracudacentral.org",
            "dnsbl.dronebl.org",
        ]
    )


class Band(BaseModel):
    good: float
    warn: float


class BufferbloatBands(BaseModel):
    a: float = 5.0
    b: float = 30.0
    c: float = 60.0
    d: float = 200.0
    e: float = 400.0


class VpnBands(BaseModel):
    likely: float = 0.40
    confirmed: float = 0.75


class Thresholds(BaseModel):
    latency_ms: Band = Band(good=40.0, warn=100.0)
    jitter_ms: Band = Band(good=5.0, warn=20.0)
    loss_pct: Band = Band(good=0.0, warn=2.0)
    bufferbloat_ms: BufferbloatBands = BufferbloatBands()
    vpn_confidence: VpnBands = VpnBands()


class Output(BaseModel):
    logs_dir: str = "./logs"
    cache_dir: str = "./.cache"
    emoji: bool = True


class Watch(BaseModel):
    interval_seconds: int = 60
    speedtest_every_n_cycles: int = 10
    dashboard_refresh_hz: int = 4


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETCHECK_",
        env_nested_delimiter="__",
        env_file_encoding="utf-8",
        extra="ignore",
        yaml_file=None,
    )

    timeouts: Timeouts = Timeouts()
    probing: Probing = Probing()
    speedtest: Speedtest = Speedtest()
    providers: Providers = Providers()
    dnsbl: Dnsbl = Dnsbl()
    thresholds: Thresholds = Thresholds()
    output: Output = Output()
    watch: Watch = Watch()

    ipinfo_token: SecretStr | None = Field(default=None, alias="IPINFO_TOKEN")
    peeringdb_api_key: SecretStr | None = Field(default=None, alias="PEERINGDB_API_KEY")
    abuseipdb_api_key: SecretStr | None = Field(default=None, alias="ABUSEIPDB_API_KEY")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


def load_settings(
    config_path: Path | None = None,
    env_file: Path | None = None,
) -> Settings:
    yaml_path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    dotenv_path = Path(env_file) if env_file is not None else DEFAULT_ENV_PATH
    Settings.model_config["yaml_file"] = yaml_path if yaml_path.exists() else None
    kwargs: dict[str, Any] = {"_env_file": str(dotenv_path) if dotenv_path.exists() else None}
    return Settings(**kwargs)
```

The secret fields carry an `alias`, so they are read as bare `IPINFO_TOKEN` rather than `NETCHECK_IPINFO_TOKEN` — the `.env.example` shipped in Task 1 uses the bare names, and a credentials file with a tool-specific prefix is friction nobody needs. Everything else is nested under `NETCHECK_` with `__` as the level separator.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_config.py -q`
Expected: PASS, 7 tests.

If `Settings(**kwargs)` rejects the aliased secret fields when populated by name, add `populate_by_name=True` to `model_config` and re-run. Do not change the alias names.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/config.py tests/test_config.py
git commit -m "config: pydantic-settings loader with env > .env > yaml precedence"
```

---

### Task 6: `orchestration.py` — `run_module` and error classification

**Files:**
- Create: `src/netcheck/orchestration.py`
- Test: `tests/test_orchestration.py`

**Interfaces:**
- Consumes: `ModuleResult`, `ProbeError` (Task 3).
- Produces:
  - `classify_exception(exc: BaseException) -> tuple[str, bool]` — returns `(kind, retryable)`
  - `async run_module(name: str, coro: Awaitable[Any], *, timeout: float, source: str | None = None) -> ModuleResult`
  - `async gather_modules(*results: Awaitable[ModuleResult]) -> list[ModuleResult]`
  - `utc_now_iso() -> str`

- [ ] **Step 1: Write the failing test**

`tests/test_orchestration.py`:

```python
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
    async def work():
        raise KeyboardInterrupt()

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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_orchestration.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.orchestration'`.

- [ ] **Step 3: Implement `src/netcheck/orchestration.py`**

```python
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
```

`KeyboardInterrupt` and `SystemExit` are `BaseException` subclasses that reach the fallback branch of `classify_exception` and become `unavailable` — that matches the test, and is the spec's "catch `BaseException` except `CancelledError`" rule (§11).

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_orchestration.py -q`
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/orchestration.py tests/test_orchestration.py
git commit -m "orchestration: run_module envelope and exception classification"
```

---

### Task 7: `netinfo.py` — capability detection

**Files:**
- Create: `src/netcheck/netinfo.py`
- Test: `tests/test_netinfo.py`

**Interfaces:**
- Consumes: `Capabilities` (Task 4).
- Produces:
  - `choose_latency_backend(caps: Capabilities) -> str` — pure
  - `choose_trace_backend(caps: Capabilities) -> str` — pure
  - `degradation_note(caps: Capabilities) -> str | None` — pure
  - `detect_capabilities() -> Capabilities` — glue (probes sockets, `shutil.which`, `ctypes`)

**Testing note:** `detect_capabilities()` itself opens real sockets and touches `ctypes`/`os.geteuid` — that is exactly the glue the testing policy says to skip. The *decision* logic it feeds (which backend wins given a set of capabilities, and what the report tells the user when everything degrades) is pure and fully tested here.

- [ ] **Step 1: Write the failing test**

`tests/test_netinfo.py`:

```python
from __future__ import annotations

from netcheck.models import Capabilities
from netcheck.netinfo import choose_latency_backend, choose_trace_backend, degradation_note


def caps(**kw) -> Capabilities:
    base = dict(os_name="Linux", is_elevated=False, icmp_dgram=False, icmp_raw=False, icmp_win_api=False)
    base.update(kw)
    return Capabilities(**base)


def test_windows_prefers_the_win32_icmp_api_over_everything():
    c = caps(os_name="Windows", icmp_win_api=True, icmp_dgram=True, icmp_raw=True)
    assert choose_latency_backend(c) == "icmp_win"


def test_unix_prefers_unprivileged_datagram_icmp():
    assert choose_latency_backend(caps(icmp_dgram=True, icmp_raw=True)) == "icmp_dgram"


def test_unix_falls_back_to_raw_icmp_when_datagram_is_unavailable():
    assert choose_latency_backend(caps(icmp_raw=True, is_elevated=True)) == "icmp_raw"


def test_latency_falls_back_to_tcp_when_no_icmp_is_possible():
    assert choose_latency_backend(caps()) == "tcp"


def test_trace_backend_prefers_mtr_when_the_binary_exists():
    c = caps(mtr_binary="/usr/bin/mtr", icmp_dgram=True, traceroute_binary="/usr/bin/traceroute")
    assert choose_trace_backend(c) == "mtr_json"


def test_trace_backend_uses_win_api_before_the_system_binary():
    c = caps(os_name="Windows", icmp_win_api=True, traceroute_binary="C:\\Windows\\System32\\TRACERT.EXE")
    assert choose_trace_backend(c) == "icmp_win"


def test_trace_backend_uses_icmplib_on_unix_before_the_system_binary():
    c = caps(icmp_dgram=True, traceroute_binary="/usr/bin/traceroute")
    assert choose_trace_backend(c) == "icmplib"


def test_trace_backend_falls_back_to_the_system_binary():
    assert choose_trace_backend(caps(traceroute_binary="/usr/bin/traceroute")) == "system_traceroute"


def test_trace_backend_reports_none_when_nothing_is_available():
    assert choose_trace_backend(caps()) == "none"


def test_degradation_note_is_absent_when_icmp_works():
    assert degradation_note(caps(icmp_dgram=True, traceroute_binary="/usr/bin/traceroute")) is None


def test_degradation_note_explains_the_tcp_fallback_with_a_remedy():
    note = degradation_note(caps())
    assert note is not None
    assert "TCP" in note
    assert "ping_group_range" in note


def test_degradation_note_on_windows_mentions_the_api_rather_than_sysctl():
    note = degradation_note(caps(os_name="Windows"))
    assert note is not None
    assert "Iphlpapi" in note
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_netinfo.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.netinfo'`.

- [ ] **Step 3: Implement the pure decision logic in `src/netcheck/netinfo.py`**

```python
from __future__ import annotations

import ctypes
import os
import platform
import shutil
import socket

from netcheck.models import Capabilities

_UNIX_REMEDY = (
    "ICMP is unavailable without privileges, so latency was measured by TCP connect timing "
    "(a different metric: 'loss' means connection failures, not dropped packets). "
    "Remedy: sysctl -w net.ipv4.ping_group_range='0 2147483647'"
)
_WINDOWS_REMEDY = (
    "ICMP is unavailable, so latency was measured by TCP connect timing "
    "(a different metric: 'loss' means connection failures, not dropped packets). "
    "Remedy: the Iphlpapi.dll IcmpSendEcho2 API is normally always present; a host firewall "
    "or security product is blocking it."
)


def choose_latency_backend(caps: Capabilities) -> str:
    if caps.icmp_win_api:
        return "icmp_win"
    if caps.icmp_dgram:
        return "icmp_dgram"
    if caps.icmp_raw:
        return "icmp_raw"
    return "tcp"


def choose_trace_backend(caps: Capabilities) -> str:
    if caps.mtr_binary:
        return "mtr_json"
    if caps.icmp_win_api:
        return "icmp_win"
    if caps.icmp_dgram or caps.icmp_raw:
        return "icmplib"
    if caps.traceroute_binary:
        return "system_traceroute"
    return "none"


def degradation_note(caps: Capabilities) -> str | None:
    if choose_latency_backend(caps) != "tcp":
        return None
    return _WINDOWS_REMEDY if caps.os_name == "Windows" else _UNIX_REMEDY
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_netinfo.py -q`
Expected: PASS, 12 tests.

- [ ] **Step 5: Add the untested detection glue to `src/netcheck/netinfo.py`**

```python
def _is_elevated() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _socket_works(family: int, sock_type: int, proto: int) -> bool:
    try:
        sock = socket.socket(family, sock_type, proto)
    except (OSError, AttributeError, PermissionError):
        return False
    sock.close()
    return True


def _win_icmp_available() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        ctypes.WinDLL("Iphlpapi.dll")
    except OSError:
        return False
    return True


def detect_capabilities() -> Capabilities:
    os_name = platform.system()
    caps = Capabilities(
        os_name=os_name,
        is_elevated=_is_elevated(),
        icmp_dgram=_socket_works(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP),
        icmp_raw=_socket_works(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
        icmp_win_api=_win_icmp_available(),
        mtr_binary=shutil.which("mtr"),
        traceroute_binary=shutil.which("tracert") if os_name == "Windows" else shutil.which("traceroute"),
    )
    caps.chosen_latency_backend = choose_latency_backend(caps)
    caps.chosen_trace_backend = choose_trace_backend(caps)
    note = degradation_note(caps)
    if note:
        caps.notes.append(note)
    return caps
```

Capability detection is attempt-based, never OS-assumption-based (spec §10): every flag above comes from actually trying the thing.

- [ ] **Step 6: Verify detection runs on this machine without raising**

Run: `uv run python -c "from netcheck.netinfo import detect_capabilities; print(detect_capabilities())"`
Expected: a `Capabilities(...)` line with a non-empty `os_name` and a `chosen_latency_backend` that is not `none`. No traceback.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/netinfo.py tests/test_netinfo.py
git commit -m "netinfo: attempt-based capability detection and backend choice"
```

---

### Task 8: `netinfo.py` — local network facts

**Files:**
- Modify: `src/netcheck/netinfo.py` (append)
- Test: `tests/test_netinfo.py` (append)

**Interfaces:**
- Consumes: `LocalNet` (Task 4), `psutil`.
- Produces:
  - `primary_interface_ip(target: str = "1.1.1.1", family: int = socket.AF_INET) -> str | None` — glue
  - `iface_for_ip(ip: str, addrs_by_iface: dict[str, list[tuple[int, str]]]) -> str | None` — pure
  - `is_tunnel_iface(name: str) -> bool` — pure
  - `mtu_anomaly(mtu: int | None) -> str | None` — pure
  - `collect_local_net() -> LocalNet` — glue

**Testing note:** `collect_local_net()` shells out to `psutil` and the OS resolver configuration; per the testing policy that is glue and stays untested. The three pure helpers it depends on — interface matching, tunnel-name recognition and MTU-anomaly classification — carry real logic and *are* tested, because Task 14's VPN scoring consumes them directly.

- [ ] **Step 1: Write the failing test (append to `tests/test_netinfo.py`)**

```python
import pytest

from netcheck.netinfo import iface_for_ip, is_tunnel_iface, mtu_anomaly


def test_iface_for_ip_matches_the_owning_adapter():
    addrs = {
        "lo": [(2, "127.0.0.1")],
        "eth0": [(2, "192.168.1.34"), (23, "fe80::1")],
        "wg0": [(2, "10.7.0.2")],
    }
    assert iface_for_ip("192.168.1.34", addrs) == "eth0"
    assert iface_for_ip("10.7.0.2", addrs) == "wg0"
    assert iface_for_ip("203.0.113.1", addrs) is None


@pytest.mark.parametrize(
    "name",
    ["tun0", "tap0", "wg0", "utun3", "ppp0", "WireGuard Tunnel", "TAP-Windows Adapter V9", "nordlynx"],
)
def test_tunnel_interfaces_are_recognised(name):
    assert is_tunnel_iface(name) is True


@pytest.mark.parametrize("name", ["eth0", "en0", "Wi-Fi", "Ethernet 2", "lo", "Loopback Pseudo-Interface 1"])
def test_ordinary_interfaces_are_not_flagged_as_tunnels(name):
    assert is_tunnel_iface(name) is False


def test_mtu_anomaly_recognises_wireguard_and_ipsec_sizes():
    assert mtu_anomaly(1420) == "wireguard"
    assert mtu_anomaly(1412) == "wireguard"
    assert mtu_anomaly(1400) == "ipsec"
    assert mtu_anomaly(1380) == "ipsec"


def test_mtu_anomaly_ignores_normal_and_unknown_values():
    assert mtu_anomaly(1500) is None
    assert mtu_anomaly(9000) is None
    assert mtu_anomaly(None) is None


def test_mtu_anomaly_flags_unusually_small_links_generically():
    assert mtu_anomaly(1200) == "small"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_netinfo.py -q`
Expected: FAIL — `ImportError: cannot import name 'iface_for_ip' from 'netcheck.netinfo'`.

- [ ] **Step 3: Append the pure helpers to `src/netcheck/netinfo.py`**

```python
import re

from netcheck.models import LocalNet

_TUNNEL_PATTERNS = (
    re.compile(r"^(tun|tap|utun|ppp|wg|nordlynx|proton|ipsec|gpd)\d*", re.IGNORECASE),
    re.compile(r"wireguard", re.IGNORECASE),
    re.compile(r"tap-windows", re.IGNORECASE),
    re.compile(r"openvpn", re.IGNORECASE),
)


def is_tunnel_iface(name: str) -> bool:
    return any(pattern.search(name) for pattern in _TUNNEL_PATTERNS)


def iface_for_ip(ip: str, addrs_by_iface: dict[str, list[tuple[int, str]]]) -> str | None:
    for iface, addrs in addrs_by_iface.items():
        for _family, address in addrs:
            if address == ip:
                return iface
    return None


def mtu_anomaly(mtu: int | None) -> str | None:
    if mtu is None or mtu >= 1500:
        return None
    if 1405 <= mtu <= 1440:
        return "wireguard"
    if 1350 <= mtu <= 1404:
        return "ipsec"
    return "small"
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_netinfo.py -q`
Expected: PASS, 26 tests.

- [ ] **Step 5: Append the collection glue to `src/netcheck/netinfo.py`**

```python
import subprocess

import psutil


def primary_interface_ip(target: str = "1.1.1.1", family: int = socket.AF_INET) -> str | None:
    # Connecting a UDP socket sends nothing; it only asks the kernel which local
    # address the route to `target` would use. This is the reliable way to pick
    # the *active* interface when several are up.
    probe = "2606:4700:4700::1111" if family == socket.AF_INET6 else target
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.connect((probe, 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _resolvers_per_adapter() -> dict[str, list[str]]:
    if platform.system() == "Windows":
        return _resolvers_windows()
    return _resolvers_unix()


def _resolvers_windows() -> dict[str, list[str]]:
    script = (
        "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | "
        "ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    adapters: dict[str, list[str]] = {}
    for line in out.splitlines():
        if "|" not in line:
            continue
        alias, _, servers = line.partition("|")
        found = [s.strip() for s in servers.split(",") if s.strip()]
        if found:
            adapters.setdefault(alias.strip(), []).extend(found)
    return adapters


def _resolvers_unix() -> dict[str, list[str]]:
    adapters: dict[str, list[str]] = {}
    try:
        text = open("/etc/resolv.conf", encoding="utf-8", errors="replace").read()
    except OSError:
        text = ""
    servers = [line.split()[1] for line in text.splitlines() if line.startswith("nameserver") and len(line.split()) > 1]
    if servers:
        adapters["system"] = servers
    try:
        scutil = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        scutil = ""
    current = None
    for line in scutil.splitlines():
        stripped = line.strip()
        if stripped.startswith("if_index"):
            current = stripped.split("(")[-1].rstrip(")") or None
        elif stripped.startswith("nameserver[") and current:
            adapters.setdefault(current, []).append(stripped.split(":", 1)[1].strip())
    return adapters


def collect_local_net() -> LocalNet:
    v4 = primary_interface_ip()
    v6 = primary_interface_ip(family=socket.AF_INET6)
    addrs_by_iface = {
        name: [(a.family, a.address.split("%")[0]) for a in addrs]
        for name, addrs in psutil.net_if_addrs().items()
    }
    iface = iface_for_ip(v4, addrs_by_iface) if v4 else None
    stats = psutil.net_if_stats()
    return LocalNet(
        iface_name=iface,
        local_ipv4=v4,
        local_ipv6=v6,
        iface_mtu=stats[iface].mtu if iface and iface in stats else None,
        default_gateway_v4=_default_gateway(socket.AF_INET),
        default_gateway_v6=_default_gateway(socket.AF_INET6),
        dns_servers_per_adapter=_resolvers_per_adapter(),
        is_dual_stack=bool(v4 and v6),
    )


def _default_gateway(family: int) -> str | None:
    if platform.system() == "Windows":
        args = ["route", "print", "-6" if family == socket.AF_INET6 else "-4"]
        needle = "::/0" if family == socket.AF_INET6 else "0.0.0.0"
    else:
        args = ["ip", "-6", "route", "show", "default"] if family == socket.AF_INET6 else ["ip", "route", "show", "default"]
        needle = "via"
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if needle not in line:
            continue
        tokens = line.split()
        if needle == "via" and "via" in tokens:
            return tokens[tokens.index("via") + 1]
        candidates = [t for t in tokens if _looks_like_ip(t)]
        if len(candidates) >= 3:
            return candidates[2]
    return None


def _looks_like_ip(token: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, token)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, token)
        return True
    except OSError:
        return False
```

- [ ] **Step 6: Verify collection runs on this machine**

Run: `uv run python -c "from netcheck.netinfo import collect_local_net; print(collect_local_net())"`
Expected: a `LocalNet(...)` line with a non-`None` `local_ipv4` and at least one entry in `dns_servers_per_adapter`. No traceback. If `default_gateway_v4` is `None` on a machine that clearly has one, that is a known-acceptable degradation — do not block on it.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/netinfo.py tests/test_netinfo.py
git commit -m "netinfo: local interface, gateway, mtu and per-adapter resolvers"
```

---
## Phase 2 — Pure logic

### Task 9: `stats.py` — RTT statistics

**Files:**
- Create: `src/netcheck/stats.py`
- Test: `tests/test_stats.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `RttStats` NamedTuple: `sent: int, received: int, loss_pct: float, min_ms: float | None, avg_ms: float | None, max_ms: float | None, mdev_ms: float | None, jitter_ms: float | None`
  - `rtt_stats(samples: list[float | None]) -> RttStats`
  - `percentile(values: list[float], p: float) -> float`

Both `probes/latency.py` (Task 25) and `traceparse.py` (Tasks 10–13) consume `rtt_stats`; `speed.py` (Task 31) consumes `percentile`. This is the spec's "jitter/loss/mdev, all-timeout and single-sample edge cases" test target (§16).

- [ ] **Step 1: Write the failing test**

`tests/test_stats.py`:

```python
from __future__ import annotations

import math

import pytest

from netcheck.stats import percentile, rtt_stats


def test_all_samples_present():
    s = rtt_stats([10.0, 12.0, 14.0, 16.0])
    assert s.sent == 4
    assert s.received == 4
    assert s.loss_pct == 0.0
    assert s.min_ms == 10.0
    assert s.max_ms == 16.0
    assert s.avg_ms == 13.0
    assert s.mdev_ms == pytest.approx(2.0)
    assert s.jitter_ms == pytest.approx(2.0)


def test_loss_is_the_share_of_missing_samples():
    s = rtt_stats([10.0, None, None, 20.0])
    assert s.sent == 4
    assert s.received == 2
    assert s.loss_pct == 50.0
    assert s.avg_ms == 15.0


def test_jitter_ignores_gaps_and_uses_consecutive_received_pairs():
    # Consecutive received pairs are (10,20) and (20,26): mean |diff| = (10+6)/2 = 8.
    s = rtt_stats([10.0, 20.0, None, 20.0, 26.0])
    assert s.jitter_ms == pytest.approx(8.0)


def test_all_timeouts_yield_full_loss_and_no_timing_values():
    s = rtt_stats([None, None, None])
    assert s.sent == 3
    assert s.received == 0
    assert s.loss_pct == 100.0
    assert s.min_ms is None
    assert s.avg_ms is None
    assert s.max_ms is None
    assert s.mdev_ms is None
    assert s.jitter_ms is None


def test_single_sample_has_zero_deviation_and_zero_jitter():
    s = rtt_stats([13.5])
    assert s.received == 1
    assert s.min_ms == s.avg_ms == s.max_ms == 13.5
    assert s.mdev_ms == 0.0
    assert s.jitter_ms == 0.0


def test_empty_input_is_not_a_division_by_zero():
    s = rtt_stats([])
    assert s.sent == 0
    assert s.received == 0
    assert s.loss_pct == 0.0
    assert s.avg_ms is None


def test_every_stat_is_finite_so_json_serialization_cannot_break():
    for samples in ([], [None], [1.0], [1.0, None, 3.0]):
        for value in rtt_stats(samples):
            assert value is None or math.isfinite(value)


def test_percentile_interpolates_between_ranks():
    values = [1.0, 2.0, 3.0, 4.0]
    assert percentile(values, 0.0) == 1.0
    assert percentile(values, 100.0) == 4.0
    assert percentile(values, 50.0) == pytest.approx(2.5)
    assert percentile(values, 90.0) == pytest.approx(3.7)


def test_percentile_handles_single_and_empty_inputs():
    assert percentile([7.0], 90.0) == 7.0
    assert percentile([], 90.0) == 0.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_stats.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.stats'`.

- [ ] **Step 3: Implement `src/netcheck/stats.py`**

```python
from __future__ import annotations

from typing import NamedTuple


class RttStats(NamedTuple):
    sent: int
    received: int
    loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    mdev_ms: float | None
    jitter_ms: float | None


def rtt_stats(samples: list[float | None]) -> RttStats:
    sent = len(samples)
    got = [s for s in samples if s is not None]
    received = len(got)
    loss_pct = 0.0 if sent == 0 else round(100.0 * (sent - received) / sent, 3)
    if not got:
        return RttStats(sent, 0, loss_pct, None, None, None, None, None)
    avg = sum(got) / received
    mdev = sum(abs(v - avg) for v in got) / received
    deltas = [
        abs(b - a)
        for a, b in zip(samples, samples[1:])
        if a is not None and b is not None
    ]
    jitter = sum(deltas) / len(deltas) if deltas else 0.0
    return RttStats(
        sent=sent,
        received=received,
        loss_pct=loss_pct,
        min_ms=round(min(got), 3),
        avg_ms=round(avg, 3),
        max_ms=round(max(got), 3),
        mdev_ms=round(mdev, 3),
        jitter_ms=round(jitter, 3),
    )


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (p / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_stats.py -q`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/stats.py tests/test_stats.py
git commit -m "stats: rtt loss, mdev and jitter with timeout-safe edge cases"
```

---

### Task 10: `traceparse.py` — Linux (GNU traceroute) parser

**Files:**
- Create: `src/netcheck/traceparse.py`
- Create: `tests/fixtures/traceroute/linux/gnu_basic.txt`, `tests/fixtures/traceroute/linux/gnu_unreachable.txt`, `tests/fixtures/traceroute/linux/gnu_maxhops.txt`
- Test: `tests/test_traceparse.py`

**Interfaces:**
- Consumes: `TraceHop` (Task 4), `rtt_stats` (Task 9).
- Produces: `parse_linux(text: str) -> list[TraceHop]`, and the internal shared helpers `finalize_hop(hop: TraceHop) -> TraceHop`, `IPV4_RE`, `IPV6_RE`, `ANNOTATION_RE` used by Tasks 11–12.

- [ ] **Step 1: Create the Linux fixtures**

`tests/fixtures/traceroute/linux/gnu_basic.txt`:

```text
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  1.234 ms  1.102 ms  1.045 ms
 2  10.64.0.1 (10.64.0.1)  8.421 ms  8.502 ms  8.377 ms
 3  * * *
 4  ae-1.r01.ams.example.net (77.88.1.5)  12.004 ms  11.883 ms  12.111 ms
 5  * 13.402 ms *
 6  one.one.one.one (1.1.1.1)  13.552 ms  13.401 ms  13.298 ms
```

`tests/fixtures/traceroute/linux/gnu_unreachable.txt`:

```text
traceroute to 203.0.113.9 (203.0.113.9), 30 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  1.100 ms  1.050 ms  1.030 ms
 2  10.64.0.1 (10.64.0.1)  8.200 ms !N  8.300 ms !N  8.250 ms !N
 3  border.example.net (198.51.100.7)  15.100 ms !H  15.200 ms  15.050 ms
```

`tests/fixtures/traceroute/linux/gnu_maxhops.txt`:

```text
traceroute to 203.0.113.200 (203.0.113.200), 5 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  1.100 ms  1.050 ms  1.030 ms
 2  * * *
 3  * * *
 4  * * *
 5  * * *
```

- [ ] **Step 2: Write the failing test**

`tests/test_traceparse.py`:

```python
from __future__ import annotations

import pytest

from netcheck.traceparse import parse_linux


@pytest.fixture()
def basic(trace_fixture):
    return parse_linux(trace_fixture("linux", "gnu_basic.txt"))


def test_linux_hop_count_ignores_the_header_line(basic):
    assert [hop.ttl for hop in basic] == [1, 2, 3, 4, 5, 6]


def test_linux_extracts_reverse_dns_and_ip(basic):
    assert basic[0].ip == "192.168.1.1"
    assert basic[0].reverse_dns == "_gateway"
    assert basic[3].ip == "77.88.1.5"
    assert basic[3].reverse_dns == "ae-1.r01.ams.example.net"


def test_linux_bare_ip_hop_has_no_reverse_dns(basic):
    assert basic[1].ip == "10.64.0.1"
    assert basic[1].reverse_dns is None


def test_linux_probe_values_are_floats_in_order(basic):
    assert basic[0].probes == [1.234, 1.102, 1.045]
    assert basic[3].probes == [12.004, 11.883, 12.111]


def test_linux_full_timeout_hop_has_three_none_probes_and_no_ip(basic):
    hop = basic[2]
    assert hop.probes == [None, None, None]
    assert hop.ip is None
    assert hop.loss_pct == 100.0
    assert hop.avg_ms is None


def test_linux_partial_timeout_hop_keeps_probe_positions(basic):
    hop = basic[4]
    assert hop.probes == [None, 13.402, None]
    assert hop.loss_pct == pytest.approx(66.667)
    assert hop.avg_ms == 13.402


def test_linux_computes_per_hop_statistics(basic):
    hop = basic[0]
    assert hop.min_ms == 1.045
    assert hop.max_ms == 1.234
    assert hop.avg_ms == pytest.approx(1.127, abs=0.001)
    assert hop.jitter_ms == pytest.approx(0.1245, abs=0.001)


def test_linux_captures_unreachable_annotations(trace_fixture):
    hops = parse_linux(trace_fixture("linux", "gnu_unreachable.txt"))
    assert hops[1].annotations == ["!N"]
    assert hops[2].annotations == ["!H"]
    assert hops[1].probes == [8.2, 8.3, 8.25]


def test_linux_max_hops_run_yields_trailing_dead_hops(trace_fixture):
    hops = parse_linux(trace_fixture("linux", "gnu_maxhops.txt"))
    assert len(hops) == 5
    assert all(h.ip is None for h in hops[1:])
    assert all(h.loss_pct == 100.0 for h in hops[1:])


def test_linux_parser_tolerates_empty_and_garbage_input():
    assert parse_linux("") == []
    assert parse_linux("bash: traceroute: command not found\n") == []
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_traceparse.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.traceparse'`.

- [ ] **Step 4: Implement `src/netcheck/traceparse.py`**

```python
from __future__ import annotations

import re

from netcheck.models import TraceHop
from netcheck.stats import rtt_stats

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
ANNOTATION_RE = re.compile(r"!\w*")
_HOP_LINE_RE = re.compile(r"^\s*(\d{1,3})\s+(.*)$")
_UNIX_PROBE_RE = re.compile(r"(?P<rtt>\d+(?:\.\d+)?)\s*ms|(?P<star>\*)")
_UNIX_HOSTIP_RE = re.compile(r"(?P<name>[A-Za-z0-9._-]+)\s+\((?P<ip>[0-9a-fA-F:.]+)\)")


def finalize_hop(hop: TraceHop) -> TraceHop:
    s = rtt_stats(hop.probes)
    hop.loss_pct = s.loss_pct
    hop.min_ms = s.min_ms
    hop.avg_ms = s.avg_ms
    hop.max_ms = s.max_ms
    hop.jitter_ms = s.jitter_ms
    return hop


def _extract_ip(text: str) -> str | None:
    v4 = IPV4_RE.search(text)
    if v4:
        return v4.group(0)
    v6 = IPV6_RE.search(text)
    return v6.group(0) if v6 else None


def _unix_host_and_ip(body: str) -> tuple[str | None, str | None]:
    match = _UNIX_HOSTIP_RE.search(body)
    if match:
        name, ip = match.group("name"), match.group("ip")
        return (None if name == ip else name), ip
    return None, _extract_ip(body)


def _unix_probes(body: str) -> list[float | None]:
    probes: list[float | None] = []
    for match in _UNIX_PROBE_RE.finditer(body):
        probes.append(None if match.group("star") else float(match.group("rtt")))
    return probes


def _unix_annotations(body: str) -> list[str]:
    seen: list[str] = []
    for token in ANNOTATION_RE.findall(body):
        if token not in seen:
            seen.append(token)
    return seen


def parse_linux(text: str) -> list[TraceHop]:
    hops: list[TraceHop] = []
    for line in text.splitlines():
        match = _HOP_LINE_RE.match(line)
        if not match:
            continue
        ttl, body = int(match.group(1)), match.group(2)
        rdns, ip = _unix_host_and_ip(body)
        hop = TraceHop(
            ttl=ttl,
            ip=ip,
            reverse_dns=rdns,
            probes=_unix_probes(body),
            annotations=_unix_annotations(body),
        )
        hops.append(finalize_hop(hop))
    return hops
```

The parser keys off line *shape* — a leading hop integer, `N ms` / `*` probe tokens, an IP regex — and never off header or footer wording. That rule exists for Windows (Task 11), but applying it uniformly keeps the three parsers structurally identical.

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_traceparse.py -q`
Expected: PASS, 10 tests.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/traceparse.py tests/test_traceparse.py tests/fixtures/traceroute/linux
git commit -m "traceparse: gnu traceroute parser with per-hop stats"
```

---

### Task 11: `traceparse.py` — Windows `tracert` parser, including cp866

**Files:**
- Modify: `src/netcheck/traceparse.py` (append)
- Create: `tests/fixtures/traceroute/windows/tracert_en.txt`, `tests/fixtures/traceroute/windows/tracert_ru_cp866.txt`, `tests/fixtures/traceroute/windows/tracert_unreachable_en.txt`
- Test: `tests/test_traceparse.py` (append)

**Interfaces:**
- Consumes: `finalize_hop`, `IPV4_RE`, `IPV6_RE` (Task 10).
- Produces: `parse_windows(text: str) -> list[TraceHop]`, `WINDOWS_SUB_MS: float`.

- [ ] **Step 1: Create the English Windows fixtures**

`tests/fixtures/traceroute/windows/tracert_en.txt` (note the leading blank line — `tracert` emits one):

```text

Tracing route to one.one.one.one [1.1.1.1]
over a maximum of 30 hops:

  1     1 ms    <1 ms     1 ms  192.168.1.1
  2     9 ms     8 ms     9 ms  10.64.0.1
  3     *        *        *     Request timed out.
  4    12 ms    12 ms    11 ms  ae-1.r01.ams.example.net [77.88.1.5]
  5    14 ms     *       13 ms  one.one.one.one [1.1.1.1]

Trace complete.
```

`tests/fixtures/traceroute/windows/tracert_unreachable_en.txt`:

```text

Tracing route to 203.0.113.9 over a maximum of 30 hops

  1     1 ms    <1 ms    <1 ms  192.168.1.1
  2    10 ms     9 ms     9 ms  10.64.0.1
  3  border.example.net [198.51.100.7]  reports: Destination net unreachable.

Trace complete.
```

- [ ] **Step 2: Create the cp866 Russian fixture**

The point of this fixture is the *encoding*, so it must be written as cp866 bytes, not UTF-8. Generate it with:

```bash
uv run python - <<'PY'
from pathlib import Path

text = """
Трассировка маршрута к one.one.one.one [1.1.1.1]
с максимальным числом прыжков 30:

  1     1 ms    <1 ms     1 ms  192.168.1.1
  2     9 ms     8 ms     9 ms  10.64.0.1
  3     *        *        *     Превышен интервал ожидания для запроса.
  4    12 ms    12 ms    11 ms  ae-1.r01.ams.example.net [77.88.1.5]
  5    14 ms     *       13 ms  one.one.one.one [1.1.1.1]

Трассировка завершена.
"""
Path("tests/fixtures/traceroute/windows/tracert_ru_cp866.txt").write_bytes(text.encode("cp866"))
PY
```

Verify it really is cp866 and not UTF-8:

```bash
uv run python -c "from pathlib import Path; b=Path('tests/fixtures/traceroute/windows/tracert_ru_cp866.txt').read_bytes(); print(len(b)); b.decode('cp866'); print('cp866 ok'); print('utf8 decodable:', True if _try(b) else False) if False else None"
uv run python -c "from pathlib import Path; b=Path('tests/fixtures/traceroute/windows/tracert_ru_cp866.txt').read_bytes(); b.decode('cp866'); print('cp866 ok'); import sys; sys.exit(0 if b.decode('utf-8','strict') else 1)" || echo "not valid utf-8 (expected)"
```

Expected: `cp866 ok` followed by `not valid utf-8 (expected)`. If the file decodes cleanly as UTF-8, it was written wrong — regenerate it.

- [ ] **Step 3: Write the failing test (append to `tests/test_traceparse.py`)**

```python
from netcheck.traceparse import WINDOWS_SUB_MS, parse_windows


@pytest.fixture()
def win_en(trace_fixture):
    return parse_windows(trace_fixture("windows", "tracert_en.txt"))


def test_windows_hop_numbers_and_count(win_en):
    assert [hop.ttl for hop in win_en] == [1, 2, 3, 4, 5]


def test_windows_sub_millisecond_probe_is_not_dropped(win_en):
    assert win_en[0].probes == [1.0, WINDOWS_SUB_MS, 1.0]
    assert 0.0 < WINDOWS_SUB_MS < 1.0


def test_windows_bracketed_ip_and_hostname_are_split(win_en):
    assert win_en[3].ip == "77.88.1.5"
    assert win_en[3].reverse_dns == "ae-1.r01.ams.example.net"


def test_windows_bare_ip_hop_has_no_reverse_dns(win_en):
    assert win_en[1].ip == "10.64.0.1"
    assert win_en[1].reverse_dns is None


def test_windows_timed_out_hop_is_detected_by_shape_not_by_message(win_en):
    hop = win_en[2]
    assert hop.probes == [None, None, None]
    assert hop.ip is None
    assert hop.loss_pct == 100.0


def test_windows_partial_timeout_keeps_probe_order(win_en):
    assert win_en[4].probes == [14.0, None, 13.0]
    assert win_en[4].ip == "1.1.1.1"


def test_windows_headers_and_footer_are_not_parsed_as_hops(win_en):
    assert all(hop.ttl <= 5 for hop in win_en)
    assert len(win_en) == 5


def test_windows_cp866_localized_output_parses_identically(trace_fixture):
    ru = parse_windows(trace_fixture("windows", "tracert_ru_cp866.txt", encoding="cp866"))
    en = parse_windows(trace_fixture("windows", "tracert_en.txt"))
    assert [h.ttl for h in ru] == [h.ttl for h in en]
    assert [h.ip for h in ru] == [h.ip for h in en]
    assert [h.probes for h in ru] == [h.probes for h in en]


def test_windows_cp866_timed_out_hop_has_no_spurious_ip(trace_fixture):
    ru = parse_windows(trace_fixture("windows", "tracert_ru_cp866.txt", encoding="cp866"))
    assert ru[2].ip is None
    assert ru[2].probes == [None, None, None]


def test_windows_destination_unreachable_hop_keeps_its_ip(trace_fixture):
    hops = parse_windows(trace_fixture("windows", "tracert_unreachable_en.txt"))
    assert hops[-1].ttl == 3
    assert hops[-1].ip == "198.51.100.7"
    assert hops[-1].probes == []
    assert hops[-1].loss_pct == 0.0


def test_windows_parser_tolerates_empty_input():
    assert parse_windows("") == []
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `uv run pytest tests/test_traceparse.py -q -k windows`
Expected: FAIL — `ImportError: cannot import name 'WINDOWS_SUB_MS' from 'netcheck.traceparse'`.

- [ ] **Step 5: Append the Windows parser to `src/netcheck/traceparse.py`**

```python
# tracert reports any sub-millisecond RTT as "<1 ms"; the midpoint of (0, 1) is
# the least-wrong single value to record for it.
WINDOWS_SUB_MS = 0.5

_WIN_PROBE_RE = re.compile(r"(?P<lt><)?\s*(?P<rtt>\d+)\s*ms|(?P<star>\*)")
_WIN_BRACKET_RE = re.compile(r"\[(?P<ip>[0-9a-fA-F:.%]+)\]")
_WIN_NAME_RE = re.compile(r"(?P<name>[A-Za-z0-9._-]+)\s*\[")


def parse_windows(text: str) -> list[TraceHop]:
    hops: list[TraceHop] = []
    for line in text.splitlines():
        match = _HOP_LINE_RE.match(line)
        if not match:
            continue
        ttl, body = int(match.group(1)), match.group(2)
        probes: list[float | None] = []
        tail_start = 0
        for probe in _WIN_PROBE_RE.finditer(body):
            if probe.group("star"):
                probes.append(None)
            else:
                probes.append(WINDOWS_SUB_MS if probe.group("lt") else float(probe.group("rtt")))
            tail_start = probe.end()
        tail = body[tail_start:]
        bracket = _WIN_BRACKET_RE.search(tail)
        if bracket:
            ip = bracket.group("ip")
            name_match = _WIN_NAME_RE.search(tail)
            rdns = name_match.group("name") if name_match else None
        else:
            ip = _extract_ip(tail)
            rdns = None
        if rdns == ip:
            rdns = None
        hops.append(finalize_hop(TraceHop(ttl=ttl, ip=ip, reverse_dns=rdns, probes=probes)))
    return hops
```

Everything after the last probe token is treated as the host field, whatever language it is written in: a timed-out hop's localized message simply contains no IP, so `ip` stays `None`. No header, footer or status string is ever matched by text.

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/test_traceparse.py -q`
Expected: PASS, 21 tests.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/traceparse.py tests/test_traceparse.py tests/fixtures/traceroute/windows
git commit -m "traceparse: windows tracert parser, shape-based and code-page safe"
```

---

### Task 12: `traceparse.py` — BSD/macOS parser

**Files:**
- Modify: `src/netcheck/traceparse.py` (append)
- Create: `tests/fixtures/traceroute/darwin/bsd_basic.txt`, `tests/fixtures/traceroute/darwin/bsd_multipath.txt`
- Test: `tests/test_traceparse.py` (append)

**Interfaces:**
- Consumes: `finalize_hop`, `_unix_probes`, `_unix_host_and_ip`, `_unix_annotations` (Task 10).
- Produces: `parse_darwin(text: str) -> list[TraceHop]`.

BSD `traceroute` differs from GNU in two ways that matter: a hop whose probes come back from different routers prints continuation lines with no leading hop number, and it emits `!H` / `!N` / `!X` annotations attached to individual probes. Extra addresses for a hop are recorded as `alt:<ip>` entries in `annotations`, because `TraceHop.ip` is a single field in the spec's data model (§4) and inventing a second field would break every consumer.

- [ ] **Step 1: Create the BSD fixtures**

`tests/fixtures/traceroute/darwin/bsd_basic.txt`:

```text
traceroute to one.one.one.one (1.1.1.1), 64 hops max, 52 byte packets
 1  192.168.1.1 (192.168.1.1)  2.145 ms  1.902 ms  1.870 ms
 2  10.64.0.1 (10.64.0.1)  9.001 ms  8.940 ms  8.870 ms
 3  * * *
 4  ae-1.r01.ams.example.net (77.88.1.5)  12.400 ms  12.100 ms  12.220 ms
 5  one.one.one.one (1.1.1.1)  13.900 ms  13.700 ms  13.610 ms
```

`tests/fixtures/traceroute/darwin/bsd_multipath.txt`:

```text
traceroute to 203.0.113.9 (203.0.113.9), 64 hops max, 52 byte packets
 1  192.168.1.1 (192.168.1.1)  2.100 ms  1.900 ms  1.850 ms
 2  10.64.0.1 (10.64.0.1)  9.001 ms
    10.64.0.5 (10.64.0.5)  9.220 ms
    10.64.0.1 (10.64.0.1)  8.870 ms
 3  * 11.200 ms *
 4  border.example.net (198.51.100.7)  15.100 ms !H  15.200 ms  15.050 ms
 5  filtered.example.net (198.51.100.9)  16.000 ms !X  16.100 ms !X  16.200 ms !X
```

- [ ] **Step 2: Write the failing test (append to `tests/test_traceparse.py`)**

```python
from netcheck.traceparse import parse_darwin


def test_darwin_basic_hops_match_the_gnu_shape(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_basic.txt"))
    assert [h.ttl for h in hops] == [1, 2, 3, 4, 5]
    assert hops[0].ip == "192.168.1.1"
    assert hops[0].reverse_dns is None
    assert hops[3].reverse_dns == "ae-1.r01.ams.example.net"
    assert hops[2].probes == [None, None, None]


def test_darwin_merges_continuation_lines_into_one_hop(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert [h.ttl for h in hops] == [1, 2, 3, 4, 5]
    hop = hops[1]
    assert hop.probes == [9.001, 9.22, 8.87]
    assert hop.ip == "10.64.0.1"


def test_darwin_records_alternate_addresses_for_a_multipath_hop(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert "alt:10.64.0.5" in hops[1].annotations
    assert "alt:10.64.0.1" not in hops[1].annotations


def test_darwin_keeps_bsd_only_annotations(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert hops[3].annotations == ["!H"]
    assert hops[4].annotations == ["!X"]


def test_darwin_partial_timeout_hop_keeps_positions(trace_fixture):
    hops = parse_darwin(trace_fixture("darwin", "bsd_multipath.txt"))
    assert hops[2].probes == [None, 11.2, None]
    assert hops[2].loss_pct == pytest.approx(66.667)


def test_darwin_parser_tolerates_empty_input():
    assert parse_darwin("") == []
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_traceparse.py -q -k darwin`
Expected: FAIL — `ImportError: cannot import name 'parse_darwin' from 'netcheck.traceparse'`.

- [ ] **Step 4: Append the BSD parser to `src/netcheck/traceparse.py`**

```python
_BSD_CONTINUATION_RE = re.compile(r"^\s+\S")


def parse_darwin(text: str) -> list[TraceHop]:
    hops: list[TraceHop] = []
    for line in text.splitlines():
        match = _HOP_LINE_RE.match(line)
        if match:
            ttl, body = int(match.group(1)), match.group(2)
            rdns, ip = _unix_host_and_ip(body)
            hops.append(
                TraceHop(
                    ttl=ttl,
                    ip=ip,
                    reverse_dns=rdns,
                    probes=_unix_probes(body),
                    annotations=_unix_annotations(body),
                )
            )
            continue
        if not hops or not _BSD_CONTINUATION_RE.match(line):
            continue
        # BSD prints one continuation line per probe that came back from a
        # different router than the hop's first probe.
        hop = hops[-1]
        _, extra_ip = _unix_host_and_ip(line)
        hop.probes.extend(_unix_probes(line))
        if extra_ip and extra_ip != hop.ip:
            marker = f"alt:{extra_ip}"
            if marker not in hop.annotations:
                hop.annotations.append(marker)
        for token in _unix_annotations(line):
            if token not in hop.annotations:
                hop.annotations.append(token)
    return [finalize_hop(hop) for hop in hops]
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_traceparse.py -q`
Expected: PASS, 27 tests.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/traceparse.py tests/test_traceparse.py tests/fixtures/traceroute/darwin
git commit -m "traceparse: bsd/macos parser with multipath hops and annotations"
```

---

### Task 13: `traceparse.py` — dispatcher and completion detection

**Files:**
- Modify: `src/netcheck/traceparse.py` (append)
- Test: `tests/test_traceparse.py` (append)

**Interfaces:**
- Consumes: `parse_linux`, `parse_windows`, `parse_darwin`.
- Produces:
  - `parse_traceroute(text: str, os_name: str) -> list[TraceHop]`
  - `build_trace_result(text: str, os_name: str, target: str, resolved_ip: str | None, backend: str = "system_traceroute", max_hops: int = 30) -> TraceResult`

`build_trace_result` is what `probes/traceroute.py` (Task 28) calls for the system-binary tier.

- [ ] **Step 1: Write the failing test (append to `tests/test_traceparse.py`)**

```python
from netcheck.traceparse import build_trace_result, parse_traceroute


def test_dispatcher_routes_by_os_name(trace_fixture):
    win = parse_traceroute(trace_fixture("windows", "tracert_en.txt"), "Windows")
    lin = parse_traceroute(trace_fixture("linux", "gnu_basic.txt"), "Linux")
    mac = parse_traceroute(trace_fixture("darwin", "bsd_basic.txt"), "Darwin")
    assert win[0].probes[1] == 0.5
    assert lin[0].probes == [1.234, 1.102, 1.045]
    assert mac[0].probes == [2.145, 1.902, 1.87]


def test_dispatcher_defaults_unknown_os_to_the_gnu_parser(trace_fixture):
    hops = parse_traceroute(trace_fixture("linux", "gnu_basic.txt"), "SunOS")
    assert [h.ttl for h in hops] == [1, 2, 3, 4, 5, 6]


def test_build_trace_result_marks_completion_when_the_target_is_reached(trace_fixture):
    result = build_trace_result(
        trace_fixture("linux", "gnu_basic.txt"),
        "Linux",
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        max_hops=30,
    )
    assert result.completed is True
    assert result.max_hops_reached is False
    assert result.backend == "system_traceroute"
    assert result.cycles == 1
    assert len(result.hops) == 6


def test_build_trace_result_flags_a_run_that_died_at_max_hops(trace_fixture):
    result = build_trace_result(
        trace_fixture("linux", "gnu_maxhops.txt"),
        "Linux",
        target="203.0.113.200",
        resolved_ip="203.0.113.200",
        max_hops=5,
    )
    assert result.completed is False
    assert result.max_hops_reached is True


def test_build_trace_result_is_not_complete_when_the_last_hop_is_a_different_host(trace_fixture):
    result = build_trace_result(
        trace_fixture("linux", "gnu_unreachable.txt"),
        "Linux",
        target="203.0.113.9",
        resolved_ip="203.0.113.9",
        max_hops=30,
    )
    assert result.completed is False
    assert result.max_hops_reached is False


def test_build_trace_result_on_empty_output_is_a_well_formed_empty_result():
    result = build_trace_result("", "Linux", target="1.1.1.1", resolved_ip=None)
    assert result.hops == []
    assert result.completed is False
    assert result.max_hops_reached is False
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_traceparse.py -q -k "dispatcher or build_trace"`
Expected: FAIL — `ImportError: cannot import name 'build_trace_result'`.

- [ ] **Step 3: Append the dispatcher to `src/netcheck/traceparse.py`**

```python
from netcheck.models import TraceResult


def parse_traceroute(text: str, os_name: str) -> list[TraceHop]:
    if os_name == "Windows":
        return parse_windows(text)
    if os_name == "Darwin":
        return parse_darwin(text)
    return parse_linux(text)


def build_trace_result(
    text: str,
    os_name: str,
    target: str,
    resolved_ip: str | None,
    backend: str = "system_traceroute",
    max_hops: int = 30,
) -> TraceResult:
    hops = parse_traceroute(text, os_name)
    completed = bool(hops and resolved_ip and hops[-1].ip == resolved_ip)
    max_hops_reached = bool(hops) and not completed and hops[-1].ttl >= max_hops
    return TraceResult(
        target=target,
        resolved_ip=resolved_ip,
        backend=backend,
        hops=hops,
        cycles=1,
        completed=completed,
        max_hops_reached=max_hops_reached,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_traceparse.py -q`
Expected: PASS, 33 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/traceparse.py tests/test_traceparse.py
git commit -m "traceparse: os dispatcher and trace completion detection"
```

---

### Task 14: `interpret.py` — thresholds to findings

**Files:**
- Create: `src/netcheck/interpret.py`
- Test: `tests/test_interpret.py`

**Interfaces:**
- Consumes: `Finding`, `PingResult`, `TraceResult`, `Signal` (Task 4); `Band`, `Thresholds` (Task 5).
- Produces:
  - `severity_for(value: float | None, band: Band, higher_is_worse: bool = True) -> str`
  - `latency_findings(pings: list[PingResult], t: Thresholds) -> list[Finding]`
  - `path_findings(trace: TraceResult) -> list[Finding]`
  - `worst(severities: Iterable[str]) -> str`

- [ ] **Step 1: Write the failing test**

`tests/test_interpret.py`:

```python
from __future__ import annotations

import pytest

from netcheck.config import Band, Thresholds
from netcheck.models import PingResult, TraceHop, TraceResult
from netcheck.interpret import latency_findings, path_findings, severity_for, worst


@pytest.fixture()
def thresholds() -> Thresholds:
    return Thresholds()


def test_severity_bands_are_inclusive_at_the_good_edge():
    band = Band(good=40.0, warn=100.0)
    assert severity_for(10.0, band) == "ok"
    assert severity_for(40.0, band) == "ok"
    assert severity_for(40.1, band) == "warn"
    assert severity_for(100.0, band) == "warn"
    assert severity_for(100.1, band) == "crit"


def test_severity_of_a_missing_value_is_info_not_ok():
    assert severity_for(None, Band(good=40.0, warn=100.0)) == "info"


def test_severity_can_be_inverted_for_metrics_where_higher_is_better():
    band = Band(good=50.0, warn=10.0)
    assert severity_for(100.0, band, higher_is_worse=False) == "ok"
    assert severity_for(50.0, band, higher_is_worse=False) == "ok"
    assert severity_for(30.0, band, higher_is_worse=False) == "warn"
    assert severity_for(5.0, band, higher_is_worse=False) == "crit"


def test_worst_picks_the_highest_severity():
    assert worst(["ok", "info", "warn"]) == "warn"
    assert worst(["ok", "crit", "warn"]) == "crit"
    assert worst([]) == "ok"
    assert worst(["ok", "ok"]) == "ok"


def ping(**kw) -> PingResult:
    base = dict(
        label="cloudflare-dns",
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_dgram",
        sent=20,
        received=20,
        loss_pct=0.0,
        min_ms=10.0,
        avg_ms=12.0,
        max_ms=15.0,
        mdev_ms=1.0,
        jitter_ms=1.0,
        samples=[],
    )
    base.update(kw)
    return PingResult(**base)


def test_a_healthy_ping_produces_no_findings(thresholds):
    assert latency_findings([ping()], thresholds) == []


def test_high_latency_produces_a_warn_finding_with_metric_and_threshold(thresholds):
    findings = latency_findings([ping(avg_ms=130.0)], thresholds)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "latency.avg.cloudflare-dns"
    assert f.severity == "crit"
    assert f.metric == "avg_ms"
    assert f.value == 130.0
    assert f.threshold == 100.0
    assert f.advice


def test_high_jitter_and_loss_each_produce_their_own_finding(thresholds):
    findings = latency_findings([ping(jitter_ms=25.0, loss_pct=5.0, received=19)], thresholds)
    ids = sorted(f.id for f in findings)
    assert ids == ["latency.jitter.cloudflare-dns", "latency.loss.cloudflare-dns"]


def test_tcp_measured_loss_is_labelled_as_connection_failures_not_packet_loss(thresholds):
    findings = latency_findings([ping(method="tcp", loss_pct=10.0)], thresholds)
    loss = [f for f in findings if f.id.startswith("latency.loss")][0]
    assert "connection failure" in loss.detail.lower()
    assert "packet loss" not in loss.detail.lower()


def test_a_fully_dead_host_is_critical_regardless_of_bands(thresholds):
    findings = latency_findings(
        [ping(received=0, loss_pct=100.0, avg_ms=None, min_ms=None, max_ms=None, jitter_ms=None)],
        thresholds,
    )
    assert [f.severity for f in findings] == ["crit"]
    assert findings[0].id == "latency.unreachable.cloudflare-dns"


def test_path_findings_highlight_the_first_sustained_loss_jump():
    trace = TraceResult(
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        backend="mtr_json",
        hops=[
            TraceHop(ttl=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.0),
            TraceHop(ttl=2, ip="10.64.0.1", loss_pct=0.0, avg_ms=9.0),
            TraceHop(ttl=3, ip="198.51.100.7", loss_pct=60.0, avg_ms=40.0),
            TraceHop(ttl=4, ip="1.1.1.1", loss_pct=55.0, avg_ms=41.0),
        ],
        completed=True,
    )
    findings = path_findings(trace)
    loss = [f for f in findings if f.id == "path.loss_jump"][0]
    assert loss.severity == "crit"
    assert "hop 3" in loss.detail
    assert "198.51.100.7" in loss.detail


def test_path_findings_ignore_a_single_hop_that_rate_limits_icmp():
    trace = TraceResult(
        target="1.1.1.1",
        resolved_ip="1.1.1.1",
        backend="mtr_json",
        hops=[
            TraceHop(ttl=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.0),
            TraceHop(ttl=2, ip="10.64.0.1", loss_pct=100.0, avg_ms=None),
            TraceHop(ttl=3, ip="1.1.1.1", loss_pct=0.0, avg_ms=12.0),
        ],
        completed=True,
    )
    assert [f.id for f in path_findings(trace)] == []


def test_path_findings_report_an_incomplete_trace():
    trace = TraceResult(target="1.1.1.1", resolved_ip="1.1.1.1", backend="icmplib", hops=[], completed=False)
    assert [f.id for f in path_findings(trace)] == ["path.incomplete"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_interpret.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.interpret'`.

- [ ] **Step 3: Implement `src/netcheck/interpret.py`**

```python
from __future__ import annotations

from typing import Iterable

from netcheck.config import Band, Thresholds
from netcheck.models import Finding, PingResult, TraceResult

_SEVERITY_ORDER = {"ok": 0, "info": 1, "warn": 2, "crit": 3}


def worst(severities: Iterable[str]) -> str:
    best = "ok"
    for severity in severities:
        if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[best]:
            best = severity
    return best


def severity_for(value: float | None, band: Band, higher_is_worse: bool = True) -> str:
    if value is None:
        return "info"
    if higher_is_worse:
        if value <= band.good:
            return "ok"
        return "warn" if value <= band.warn else "crit"
    if value >= band.good:
        return "ok"
    return "warn" if value >= band.warn else "crit"


def latency_findings(pings: list[PingResult], t: Thresholds) -> list[Finding]:
    findings: list[Finding] = []
    for p in pings:
        if p.received == 0:
            findings.append(
                Finding(
                    id=f"latency.unreachable.{p.label}",
                    severity="crit",
                    title=f"{p.host} did not answer",
                    detail=f"{p.sent} probes sent via {p.method}, none returned.",
                    metric="received",
                    value=0,
                    threshold=1,
                    advice="If every reference host is unreachable the link is down or filtering the probe method.",
                )
            )
            continue
        severity = severity_for(p.avg_ms, t.latency_ms)
        if severity not in ("ok", "info"):
            findings.append(
                Finding(
                    id=f"latency.avg.{p.label}",
                    severity=severity,
                    title=f"Latency to {p.host} above target",
                    detail=f"Average {p.avg_ms} ms over {p.received} probes via {p.method}.",
                    metric="avg_ms",
                    value=p.avg_ms,
                    threshold=t.latency_ms.warn,
                    advice="Check for a saturated uplink, a distant route, or a congested Wi-Fi link.",
                )
            )
        severity = severity_for(p.jitter_ms, t.jitter_ms)
        if severity not in ("ok", "info"):
            findings.append(
                Finding(
                    id=f"latency.jitter.{p.label}",
                    severity=severity,
                    title=f"Jitter to {p.host} above target",
                    detail=f"Jitter {p.jitter_ms} ms over {p.received} probes via {p.method}.",
                    metric="jitter_ms",
                    value=p.jitter_ms,
                    threshold=t.jitter_ms.warn,
                    advice="Unstable latency hurts calls and games more than raw latency does.",
                )
            )
        severity = severity_for(p.loss_pct, t.loss_pct)
        if severity not in ("ok", "info"):
            kind = "connection failures" if p.method == "tcp" else "packet loss"
            findings.append(
                Finding(
                    id=f"latency.loss.{p.label}",
                    severity=severity,
                    title=f"Loss to {p.host}",
                    detail=f"{p.loss_pct}% {kind} over {p.sent} probes via {p.method}.",
                    metric="loss_pct",
                    value=p.loss_pct,
                    threshold=t.loss_pct.warn,
                    advice="Sustained loss on every host points at the local link or the first upstream hop.",
                )
            )
    return findings


def path_findings(trace: TraceResult) -> list[Finding]:
    if not trace.hops:
        return [
            Finding(
                id="path.incomplete",
                severity="info",
                title="No path data",
                detail=f"The traceroute to {trace.target} returned no hops (backend {trace.backend}).",
                advice="ICMP may be filtered end to end; try --tcp-trace.",
            )
        ]
    findings: list[Finding] = []
    for index, hop in enumerate(trace.hops[:-1]):
        following = trace.hops[index + 1]
        # A single lossy hop with clean hops after it is ICMP rate limiting on that
        # router, not a real problem; loss that persists to the next hop is real.
        if hop.loss_pct >= 20.0 and following.loss_pct >= 20.0:
            findings.append(
                Finding(
                    id="path.loss_jump",
                    severity="crit" if hop.loss_pct >= 50.0 else "warn",
                    title="Sustained loss starts mid-path",
                    detail=f"Loss appears at hop {hop.ttl} ({hop.ip}) at {hop.loss_pct}% and persists downstream.",
                    metric="loss_pct",
                    value=hop.loss_pct,
                    threshold=20.0,
                    advice="This hop and everything after it share the problem; the hop before it is the last clean one.",
                )
            )
            break
    if not trace.completed:
        findings.append(
            Finding(
                id="path.incomplete",
                severity="info",
                title="Path did not reach the target",
                detail=f"The trace to {trace.target} stopped at hop {trace.hops[-1].ttl}.",
                advice="Many networks drop the final ICMP reply; this alone is not a fault.",
            )
        )
    return findings
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_interpret.py -q`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/interpret.py tests/test_interpret.py
git commit -m "interpret: threshold bands, latency and path findings"
```

---

### Task 15: `interpret.py` — VPN confidence scoring

**Files:**
- Modify: `src/netcheck/interpret.py` (append)
- Test: `tests/test_interpret.py` (append)

**Interfaces:**
- Consumes: `Signal`, `VpnAssessment`, `DnsLeak`, `IpGeo`, `LocalNet`, `CfTrace` (Task 4); `VpnBands` (Task 5); `is_tunnel_iface`, `mtu_anomaly` (Task 8).
- Produces:
  - `SIGNAL_WEIGHTS: dict[str, float]`
  - `gather_vpn_signals(local: LocalNet, geo: IpGeo, cf: CfTrace | None, dns_leak: DnsLeak | None, pdb_info_type: str | None, os_timezone: str | None, provider_flags: dict[str, bool]) -> list[Signal]`
  - `score_vpn(signals: list[Signal], bands: VpnBands) -> tuple[str, float]`
  - `assess_vpn(signals: list[Signal], bands: VpnBands, tunnel_iface: str | None, dns_leak: DnsLeak | None) -> VpnAssessment`

- [ ] **Step 1: Write the failing test (append to `tests/test_interpret.py`)**

```python
from netcheck.config import VpnBands
from netcheck.models import AdapterLeakResult, CfTrace, DnsLeak, IpGeo, LocalNet, Signal
from netcheck.interpret import SIGNAL_WEIGHTS, assess_vpn, gather_vpn_signals, score_vpn


def sig(name: str, observed: bool = True) -> Signal:
    return Signal(name=name, observed=observed, weight=SIGNAL_WEIGHTS[name], direction="vpn")


def test_no_signals_means_no_vpn():
    verdict, confidence = score_vpn([], VpnBands())
    assert verdict == "none"
    assert confidence == 0.0


def test_unobserved_signals_contribute_nothing():
    verdict, confidence = score_vpn(
        [sig("tunnel_iface", observed=False), sig("cf_warp", observed=False)], VpnBands()
    )
    assert verdict == "none"
    assert confidence == 0.0


def test_cloudflare_warp_alone_is_enough_for_likely():
    verdict, confidence = score_vpn([sig("cf_warp")], VpnBands())
    assert verdict == "likely"
    assert confidence == pytest.approx(0.50)


def test_tunnel_interface_plus_hosting_egress_is_confirmed():
    verdict, confidence = score_vpn([sig("tunnel_iface"), sig("provider_hosting")], VpnBands())
    assert verdict == "confirmed"
    assert confidence >= 0.75


def test_a_mobile_flag_with_a_timezone_mismatch_does_not_fire():
    # This combination is normal for anyone travelling on a phone hotspot and
    # must not be reported as a VPN.
    verdict, confidence = score_vpn([sig("provider_mobile"), sig("timezone_mismatch")], VpnBands())
    assert verdict == "none"
    assert confidence < 0.40


def test_mtu_anomaly_alone_does_not_fire():
    verdict, _ = score_vpn([sig("mtu_anomaly")], VpnBands())
    assert verdict == "none"


def test_dns_asn_mismatch_alone_does_not_fire():
    verdict, _ = score_vpn([sig("dns_asn_mismatch")], VpnBands())
    assert verdict == "none"


def test_mtu_anomaly_plus_tunnel_iface_plus_dns_mismatch_is_confirmed():
    verdict, confidence = score_vpn(
        [sig("tunnel_iface"), sig("mtu_anomaly"), sig("dns_asn_mismatch")], VpnBands()
    )
    assert verdict == "confirmed"
    assert confidence == pytest.approx(0.80)


def test_confidence_is_capped_at_one():
    _, confidence = score_vpn([sig(name) for name in SIGNAL_WEIGHTS], VpnBands())
    assert confidence == 1.0


def test_clean_direction_signals_reduce_confidence():
    signals = [
        sig("provider_hosting"),
        Signal(name="pdb_eyeball_isp", observed=True, weight=0.2, direction="clean"),
    ]
    _, confidence = score_vpn(signals, VpnBands())
    assert confidence == pytest.approx(0.20)


def test_gather_signals_flags_a_wireguard_tunnel_with_a_hosting_egress():
    local = LocalNet(iface_name="wg0", local_ipv4="10.7.0.2", iface_mtu=1420, default_gateway_v4="10.7.0.1")
    geo = IpGeo(ip="203.0.113.44", asn="AS64500", country_code="NL", timezone="Europe/Amsterdam")
    signals = {s.name: s for s in gather_vpn_signals(
        local=local,
        geo=geo,
        cf=CfTrace(ip="203.0.113.44", warp="off"),
        dns_leak=None,
        pdb_info_type="NSP",
        os_timezone="Europe/Amsterdam",
        provider_flags={"hosting": True, "proxy": False, "mobile": False},
    )}
    assert signals["tunnel_iface"].observed is True
    assert signals["tunnel_iface"].note == "wg0"
    assert signals["mtu_anomaly"].observed is True
    assert signals["mtu_anomaly"].note == "wireguard"
    assert signals["provider_hosting"].observed is True
    assert signals["cf_warp"].observed is False
    assert signals["timezone_mismatch"].observed is False


def test_gather_signals_detects_a_dns_resolver_in_another_asn():
    leak = DnsLeak(
        per_adapter=[
            AdapterLeakResult(
                adapter="Wi-Fi",
                configured_resolvers=["192.168.1.1"],
                echoed_ip="203.0.113.9",
                echoed_asn="AS64501",
                matches_egress_asn=False,
            )
        ]
    )
    signals = {s.name: s for s in gather_vpn_signals(
        local=LocalNet(iface_name="eth0"),
        geo=IpGeo(asn="AS64500"),
        cf=None,
        dns_leak=leak,
        pdb_info_type=None,
        os_timezone=None,
        provider_flags={},
    )}
    assert signals["dns_asn_mismatch"].observed is True
    assert "Wi-Fi" in signals["dns_asn_mismatch"].note


def test_gather_signals_detects_cloudflare_warp():
    signals = {s.name: s for s in gather_vpn_signals(
        local=LocalNet(),
        geo=IpGeo(),
        cf=CfTrace(warp="on"),
        dns_leak=None,
        pdb_info_type=None,
        os_timezone=None,
        provider_flags={},
    )}
    assert signals["cf_warp"].observed is True


def test_assess_vpn_returns_a_complete_assessment():
    assessment = assess_vpn(
        signals=[sig("tunnel_iface"), sig("provider_hosting")],
        bands=VpnBands(),
        tunnel_iface="wg0",
        dns_leak=None,
    )
    assert assessment.verdict == "confirmed"
    assert assessment.tunnel_iface == "wg0"
    assert len(assessment.signals) == 2
    assert assessment.confidence >= 0.75
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_interpret.py -q -k vpn`
Expected: FAIL — `ImportError: cannot import name 'SIGNAL_WEIGHTS' from 'netcheck.interpret'`.

- [ ] **Step 3: Append the VPN scoring to `src/netcheck/interpret.py`**

```python
from netcheck.config import VpnBands
from netcheck.models import CfTrace, DnsLeak, IpGeo, LocalNet, Signal, VpnAssessment
from netcheck.netinfo import is_tunnel_iface, mtu_anomaly

SIGNAL_WEIGHTS: dict[str, float] = {
    "tunnel_iface": 0.35,
    "cf_warp": 0.50,
    "provider_proxy": 0.35,
    "provider_hosting": 0.40,
    "provider_mobile": 0.10,
    "mtu_anomaly": 0.20,
    "dns_asn_mismatch": 0.25,
    "gateway_egress_mismatch": 0.15,
    "pdb_info_type_nsp": 0.15,
    "timezone_mismatch": 0.15,
}

_TZ_COUNTRY_PREFIX = {
    "Europe/Amsterdam": "NL",
    "Europe/Moscow": "RU",
    "Europe/London": "GB",
    "Europe/Berlin": "DE",
    "America/New_York": "US",
    "America/Los_Angeles": "US",
    "Asia/Tokyo": "JP",
}


def _signal(name: str, observed: bool, note: str = "") -> Signal:
    return Signal(name=name, observed=observed, weight=SIGNAL_WEIGHTS[name], direction="vpn", note=note)


def gather_vpn_signals(
    local: LocalNet,
    geo: IpGeo,
    cf: CfTrace | None,
    dns_leak: DnsLeak | None,
    pdb_info_type: str | None,
    os_timezone: str | None,
    provider_flags: dict[str, bool],
) -> list[Signal]:
    iface = local.iface_name or ""
    anomaly = mtu_anomaly(local.iface_mtu)
    leaking = [
        a
        for a in (dns_leak.per_adapter if dns_leak else [])
        if a.matches_egress_asn is False
    ]
    tz_country = _TZ_COUNTRY_PREFIX.get(os_timezone or "")
    return [
        _signal("tunnel_iface", is_tunnel_iface(iface), iface),
        _signal("cf_warp", bool(cf and (cf.warp or "").lower() == "on"), (cf.warp if cf else "") or ""),
        _signal("provider_proxy", bool(provider_flags.get("proxy"))),
        _signal("provider_hosting", bool(provider_flags.get("hosting"))),
        _signal("provider_mobile", bool(provider_flags.get("mobile"))),
        _signal("mtu_anomaly", anomaly in ("wireguard", "ipsec"), anomaly or ""),
        _signal(
            "dns_asn_mismatch",
            bool(leaking),
            ", ".join(f"{a.adapter} -> {a.echoed_asn}" for a in leaking),
        ),
        _signal(
            "gateway_egress_mismatch",
            bool(local.default_gateway_v4 and is_tunnel_iface(iface)),
            local.default_gateway_v4 or "",
        ),
        _signal("pdb_info_type_nsp", (pdb_info_type or "").upper() in ("NSP", "CONTENT", "ENTERPRISE"), pdb_info_type or ""),
        _signal(
            "timezone_mismatch",
            bool(tz_country and geo.country_code and tz_country != geo.country_code),
            f"{os_timezone} vs {geo.country_code}" if tz_country else "",
        ),
    ]


def score_vpn(signals: list[Signal], bands: VpnBands) -> tuple[str, float]:
    total = 0.0
    for s in signals:
        if not s.observed:
            continue
        total += s.weight if s.direction == "vpn" else -s.weight
    confidence = round(max(0.0, min(1.0, total)), 3)
    if confidence >= bands.confirmed:
        return "confirmed", confidence
    if confidence >= bands.likely:
        return "likely", confidence
    return "none", confidence


def assess_vpn(
    signals: list[Signal],
    bands: VpnBands,
    tunnel_iface: str | None,
    dns_leak: DnsLeak | None,
) -> VpnAssessment:
    verdict, confidence = score_vpn(signals, bands)
    return VpnAssessment(
        verdict=verdict,
        confidence=confidence,
        signals=signals,
        tunnel_iface=tunnel_iface,
        dns_leak=dns_leak,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_interpret.py -q`
Expected: PASS, 26 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/interpret.py tests/test_interpret.py
git commit -m "interpret: weighted vpn confidence scoring"
```

---

### Task 16: `interpret.py` — bufferbloat grade and overall verdict

**Files:**
- Modify: `src/netcheck/interpret.py` (append)
- Test: `tests/test_interpret.py` (append)

**Interfaces:**
- Consumes: `BufferbloatBands` (Task 5), `SpeedResult`, `Finding` (Task 4).
- Produces:
  - `grade_bufferbloat(delta_ms: float | None, bands: BufferbloatBands) -> str`
  - `bufferbloat_consequence(grade: str) -> str`
  - `speed_findings(speed: SpeedResult, bands: BufferbloatBands) -> list[Finding]`
  - `overall_verdict(findings: list[Finding]) -> tuple[str, int, str]` — returns `(overall_status, overall_score, summary_text)`

- [ ] **Step 1: Write the failing test (append to `tests/test_interpret.py`)**

```python
from netcheck.config import BufferbloatBands
from netcheck.models import Finding, SpeedResult
from netcheck.interpret import bufferbloat_consequence, grade_bufferbloat, overall_verdict, speed_findings


def test_bufferbloat_grades_follow_the_configured_bands():
    b = BufferbloatBands()
    assert grade_bufferbloat(0.0, b) == "A"
    assert grade_bufferbloat(5.0, b) == "A"
    assert grade_bufferbloat(5.1, b) == "B"
    assert grade_bufferbloat(30.0, b) == "B"
    assert grade_bufferbloat(60.0, b) == "C"
    assert grade_bufferbloat(200.0, b) == "D"
    assert grade_bufferbloat(400.0, b) == "E"
    assert grade_bufferbloat(400.1, b) == "F"


def test_bufferbloat_grade_of_an_unmeasured_delta_is_unknown():
    assert grade_bufferbloat(None, BufferbloatBands()) == "?"


def test_negative_delta_is_graded_a_not_crashed():
    assert grade_bufferbloat(-3.0, BufferbloatBands()) == "A"


def test_each_grade_has_a_plain_language_consequence():
    for grade in "ABCDEF?":
        assert bufferbloat_consequence(grade)
    assert "call" in bufferbloat_consequence("F").lower()


def test_speed_findings_report_a_bad_bufferbloat_grade():
    speed = SpeedResult(method="cloudflare", download_mbps=300.0, upload_mbps=40.0, bufferbloat_down_ms=250.0)
    findings = speed_findings(speed, BufferbloatBands())
    bloat = [f for f in findings if f.id == "speed.bufferbloat_down"][0]
    assert bloat.severity == "crit"
    assert bloat.value == "D"
    assert "call" in bloat.advice.lower() or "queue" in bloat.advice.lower()


def test_speed_findings_are_silent_on_a_clean_line():
    speed = SpeedResult(
        method="ookla_bin",
        download_mbps=300.0,
        upload_mbps=40.0,
        bufferbloat_down_ms=3.0,
        bufferbloat_up_ms=4.0,
    )
    assert speed_findings(speed, BufferbloatBands()) == []


def test_speed_findings_report_an_exhausted_cascade():
    speed = SpeedResult(method="none")
    findings = speed_findings(speed, BufferbloatBands())
    assert [f.id for f in findings] == ["speed.unavailable"]
    assert findings[0].severity == "info"


def test_overall_verdict_is_healthy_with_no_findings():
    status, score, summary = overall_verdict([])
    assert status == "ok"
    assert score == 100
    assert "no problems" in summary.lower()


def test_overall_verdict_degrades_with_severity():
    warn = Finding(id="a", severity="warn", title="Jitter high", detail="")
    crit = Finding(id="b", severity="crit", title="Loss on path", detail="")
    info = Finding(id="c", severity="info", title="No speed data", detail="")

    status, score, summary = overall_verdict([info])
    assert (status, score) == ("ok", 97)

    status, score, summary = overall_verdict([warn])
    assert status == "warn"
    assert score == 90

    status, score, summary = overall_verdict([warn, crit])
    assert status == "crit"
    assert score == 65
    assert "Loss on path" in summary


def test_overall_score_never_goes_below_zero():
    findings = [Finding(id=f"f{i}", severity="crit", title="x", detail="") for i in range(20)]
    status, score, _ = overall_verdict(findings)
    assert status == "crit"
    assert score == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_interpret.py -q -k "bufferbloat or overall or speed_findings"`
Expected: FAIL — `ImportError: cannot import name 'grade_bufferbloat'`.

- [ ] **Step 3: Append to `src/netcheck/interpret.py`**

```python
from netcheck.config import BufferbloatBands
from netcheck.models import SpeedResult

_CONSEQUENCES = {
    "A": "Video calls and games stay smooth while the line is fully loaded.",
    "B": "Barely noticeable; a large upload may add a beat to a video call.",
    "C": "Calls and games get choppy whenever something else is downloading.",
    "D": "Any big transfer makes calls stutter and pages feel stuck.",
    "E": "The connection feels broken while it is busy, even though bandwidth is fine.",
    "F": "A single download makes a call unusable; this is queue bloat, not a slow line.",
    "?": "Not measured — the speedtest tier that measures it did not run.",
}
_GRADE_SEVERITY = {"A": "ok", "B": "ok", "C": "warn", "D": "crit", "E": "crit", "F": "crit", "?": "info"}


def grade_bufferbloat(delta_ms: float | None, bands: BufferbloatBands) -> str:
    if delta_ms is None:
        return "?"
    delta = max(0.0, delta_ms)
    for grade, ceiling in (("A", bands.a), ("B", bands.b), ("C", bands.c), ("D", bands.d), ("E", bands.e)):
        if delta <= ceiling:
            return grade
    return "F"


def bufferbloat_consequence(grade: str) -> str:
    return _CONSEQUENCES.get(grade, _CONSEQUENCES["?"])


def speed_findings(speed: SpeedResult, bands: BufferbloatBands) -> list[Finding]:
    if speed.method == "none":
        tried = ", ".join(a.tier for a in speed.tier_attempts) or "none"
        return [
            Finding(
                id="speed.unavailable",
                severity="info",
                title="No bandwidth measurement",
                detail=f"Every speedtest tier failed or was disabled (tried: {tried}).",
                advice="Install the Ookla speedtest binary, or rerun without --quick.",
            )
        ]
    findings: list[Finding] = []
    for direction, delta in (("down", speed.bufferbloat_down_ms), ("up", speed.bufferbloat_up_ms)):
        grade = grade_bufferbloat(delta, bands)
        severity = _GRADE_SEVERITY[grade]
        if severity in ("ok", "info"):
            continue
        findings.append(
            Finding(
                id=f"speed.bufferbloat_{direction}",
                severity=severity,
                title=f"Bufferbloat under load ({direction}stream): grade {grade}",
                detail=f"Latency rose by {delta} ms while saturating the {direction}stream direction.",
                metric=f"bufferbloat_{direction}_ms",
                value=grade,
                threshold=bands.c,
                advice=bufferbloat_consequence(grade)
                + " Enabling SQM/fq_codel on the router is the standard fix.",
            )
        )
    return findings


_SCORE_PENALTY = {"ok": 0, "info": 3, "warn": 10, "crit": 25}


def overall_verdict(findings: list[Finding]) -> tuple[str, int, str]:
    score = 100
    for f in findings:
        score -= _SCORE_PENALTY[f.severity]
    score = max(0, score)
    status = worst(f.severity for f in findings)
    if status in ("ok", "info"):
        return "ok", score, "No problems found on this connection."
    headline = [f.title for f in findings if f.severity == status]
    return status, score, "; ".join(headline[:3])
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_interpret.py -q`
Expected: PASS, 36 tests.

- [ ] **Step 5: Run the full suite to confirm nothing regressed**

Run: `uv run pytest -q`
Expected: PASS, ~120 tests, no failures.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/interpret.py tests/test_interpret.py
git commit -m "interpret: bufferbloat grading and overall verdict scoring"
```

---
## Phase 3 — Providers

### Task 17: `ip_geo.py` — per-provider normalizers

**Files:**
- Create: `src/netcheck/ip_geo.py`
- Create: `tests/fixtures/api/ip_api.json`, `tests/fixtures/api/ip_api_fail.json`, `tests/fixtures/api/freeipapi.json`, `tests/fixtures/api/ipinfo.json`, `tests/fixtures/api/ipwhois.json`, `tests/fixtures/api/ripestat_network_info.json`, `tests/fixtures/api/cf_trace.txt`
- Test: `tests/test_ip_geo_normalize.py`

**Interfaces:**
- Consumes: `IpGeo`, `CfTrace` (Task 4).
- Produces:
  - `classify_ip_type(mobile: bool, proxy: bool, hosting: bool, known: bool) -> str`
  - `normalize_ip_api(payload: dict) -> IpGeo`
  - `normalize_freeipapi(payload: dict) -> IpGeo`
  - `normalize_ipinfo(payload: dict) -> IpGeo`
  - `normalize_ipwhois(payload: dict) -> IpGeo`
  - `normalize_ripestat_network_info(payload: dict) -> IpGeo`
  - `parse_cf_trace(text: str) -> CfTrace`
  - `provider_flags(payload: dict) -> dict[str, bool]`

- [ ] **Step 1: Create the provider fixtures**

`tests/fixtures/api/ip_api.json`:

```json
{
  "status": "success",
  "country": "Netherlands",
  "countryCode": "NL",
  "region": "NH",
  "regionName": "North Holland",
  "city": "Amsterdam",
  "zip": "1012",
  "lat": 52.3759,
  "lon": 4.8975,
  "timezone": "Europe/Amsterdam",
  "isp": "Example Telecom",
  "org": "Example Telecom BV",
  "as": "AS64500 Example Telecom",
  "asname": "EXAMPLE-AS",
  "reverse": "host-203-0-113-44.example.net",
  "mobile": false,
  "proxy": false,
  "hosting": true,
  "query": "203.0.113.44"
}
```

`tests/fixtures/api/ip_api_fail.json`:

```json
{
  "status": "fail",
  "message": "private range",
  "query": "192.168.1.34"
}
```

`tests/fixtures/api/freeipapi.json`:

```json
{
  "ipVersion": 4,
  "ipAddress": "203.0.113.44",
  "latitude": 52.3759,
  "longitude": 4.8975,
  "countryName": "Netherlands",
  "countryCode": "NL",
  "timeZone": "+02:00",
  "zipCode": "1012",
  "cityName": "Amsterdam",
  "regionName": "North Holland",
  "isProxy": false,
  "continent": "Europe",
  "asn": "64500",
  "asnOrganization": "Example Telecom BV"
}
```

`tests/fixtures/api/ipinfo.json`:

```json
{
  "ip": "203.0.113.44",
  "hostname": "host-203-0-113-44.example.net",
  "city": "Amsterdam",
  "region": "North Holland",
  "country": "NL",
  "loc": "52.3759,4.8975",
  "org": "AS64500 Example Telecom BV",
  "postal": "1012",
  "timezone": "Europe/Amsterdam"
}
```

`tests/fixtures/api/ipwhois.json`:

```json
{
  "ip": "203.0.113.44",
  "success": true,
  "type": "IPv4",
  "continent": "Europe",
  "country": "Netherlands",
  "country_code": "NL",
  "region": "North Holland",
  "city": "Amsterdam",
  "latitude": 52.3759,
  "longitude": 4.8975,
  "connection": {
    "asn": 64500,
    "org": "Example Telecom BV",
    "isp": "Example Telecom",
    "domain": "example.net"
  },
  "timezone": { "id": "Europe/Amsterdam", "utc": "+02:00" }
}
```

`tests/fixtures/api/ripestat_network_info.json`:

```json
{
  "status": "ok",
  "data_call_name": "network-info",
  "data": {
    "asns": ["64500"],
    "prefix": "203.0.113.0/24"
  }
}
```

`tests/fixtures/api/cf_trace.txt`:

```text
fl=123f45
h=www.cloudflare.com
ip=203.0.113.44
ts=1786000000.123
visit_scheme=https
uag=netcheck/0.1.0
colo=AMS
sliver=none
http=http/2
loc=NL
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519
```

- [ ] **Step 2: Write the failing test**

`tests/test_ip_geo_normalize.py`:

```python
from __future__ import annotations

import pytest

from netcheck.ip_geo import (
    classify_ip_type,
    normalize_freeipapi,
    normalize_ip_api,
    normalize_ipinfo,
    normalize_ipwhois,
    normalize_ripestat_network_info,
    parse_cf_trace,
    provider_flags,
)


def test_ip_api_normalizes_to_the_common_shape(api_fixture):
    geo = normalize_ip_api(api_fixture("ip_api.json"))
    assert geo.ip == "203.0.113.44"
    assert geo.ip_version == 4
    assert geo.asn == "AS64500"
    assert geo.as_name == "Example Telecom"
    assert geo.org == "Example Telecom BV"
    assert geo.country == "Netherlands"
    assert geo.country_code == "NL"
    assert geo.city == "Amsterdam"
    assert geo.lat == 52.3759
    assert geo.lon == 4.8975
    assert geo.timezone == "Europe/Amsterdam"
    assert geo.reverse_dns == "host-203-0-113-44.example.net"
    assert geo.ip_type == "hosting"


def test_ip_api_failure_payload_yields_an_empty_geo_not_an_exception(api_fixture):
    geo = normalize_ip_api(api_fixture("ip_api_fail.json"))
    assert geo.asn is None
    assert geo.country is None
    assert geo.ip_type == "unknown"


def test_freeipapi_normalizes_and_prefixes_the_bare_asn(api_fixture):
    geo = normalize_freeipapi(api_fixture("freeipapi.json"))
    assert geo.ip == "203.0.113.44"
    assert geo.ip_version == 4
    assert geo.asn == "AS64500"
    assert geo.org == "Example Telecom BV"
    assert geo.country_code == "NL"
    assert geo.city == "Amsterdam"
    assert geo.ip_type == "residential"


def test_ipinfo_splits_the_org_field_into_asn_and_name(api_fixture):
    geo = normalize_ipinfo(api_fixture("ipinfo.json"))
    assert geo.asn == "AS64500"
    assert geo.as_name == "Example Telecom BV"
    assert geo.lat == 52.3759
    assert geo.lon == 4.8975
    assert geo.country_code == "NL"
    assert geo.reverse_dns == "host-203-0-113-44.example.net"


def test_ipinfo_without_a_loc_field_does_not_crash():
    geo = normalize_ipinfo({"ip": "203.0.113.44", "org": "AS64500 Example"})
    assert geo.lat is None
    assert geo.lon is None


def test_ipwhois_reads_the_nested_connection_and_timezone_objects(api_fixture):
    geo = normalize_ipwhois(api_fixture("ipwhois.json"))
    assert geo.asn == "AS64500"
    assert geo.as_name == "Example Telecom"
    assert geo.org == "Example Telecom BV"
    assert geo.timezone == "Europe/Amsterdam"
    assert geo.ip_version == 4
    assert geo.country_code == "NL"


def test_ripestat_network_info_gives_authoritative_asn_only(api_fixture):
    geo = normalize_ripestat_network_info(api_fixture("ripestat_network_info.json"))
    assert geo.asn == "AS64500"
    assert geo.city is None
    assert geo.sources == {"asn": "ripestat"}


def test_cf_trace_parses_every_key_and_the_vpn_relevant_flags(fixtures_dir):
    cf = parse_cf_trace((fixtures_dir / "api" / "cf_trace.txt").read_text(encoding="utf-8"))
    assert cf.ip == "203.0.113.44"
    assert cf.colo == "AMS"
    assert cf.loc == "NL"
    assert cf.warp == "off"
    assert cf.gateway == "off"
    assert cf.rbi == "off"
    assert cf.raw["tls"] == "TLSv1.3"


def test_cf_trace_tolerates_blank_lines_and_missing_keys():
    cf = parse_cf_trace("ip=1.2.3.4\n\nnot-a-pair\ncolo=AMS\n")
    assert cf.ip == "1.2.3.4"
    assert cf.colo == "AMS"
    assert cf.warp is None


def test_provider_flags_reads_the_ip_api_booleans(api_fixture):
    assert provider_flags(api_fixture("ip_api.json")) == {
        "mobile": False,
        "proxy": False,
        "hosting": True,
    }


def test_provider_flags_of_a_failed_payload_is_empty(api_fixture):
    assert provider_flags(api_fixture("ip_api_fail.json")) == {}


@pytest.mark.parametrize(
    ("mobile", "proxy", "hosting", "known", "expected"),
    [
        (False, False, False, False, "unknown"),
        (False, False, False, True, "residential"),
        (True, False, False, True, "mobile"),
        (True, False, True, True, "mobile"),
        (False, True, False, True, "hosting"),
        (False, False, True, True, "hosting"),
    ],
)
def test_ip_type_classification(mobile, proxy, hosting, known, expected):
    assert classify_ip_type(mobile, proxy, hosting, known) == expected
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_ip_geo_normalize.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.ip_geo'`.

- [ ] **Step 4: Implement the normalizers in `src/netcheck/ip_geo.py`**

```python
from __future__ import annotations

import ipaddress
import re

from netcheck.models import CfTrace, IpGeo

_AS_PREFIX_RE = re.compile(r"^AS(\d+)\s*(?P<name>.*)$", re.IGNORECASE)


def _as_number(value: object) -> str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    match = _AS_PREFIX_RE.match(text)
    if match:
        return f"AS{match.group(1)}"
    if text.isdigit():
        return f"AS{text}"
    return None


def _as_label(value: object) -> str | None:
    match = _AS_PREFIX_RE.match(str(value or ""))
    name = (match.group("name") if match else "").strip()
    return name or None


def _ip_version(ip: str | None) -> int | None:
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def classify_ip_type(mobile: bool, proxy: bool, hosting: bool, known: bool) -> str:
    if not known:
        return "unknown"
    if mobile:
        return "mobile"
    if hosting or proxy:
        return "hosting"
    return "residential"


def provider_flags(payload: dict) -> dict[str, bool]:
    if payload.get("status") != "success":
        return {}
    return {
        "mobile": bool(payload.get("mobile")),
        "proxy": bool(payload.get("proxy")),
        "hosting": bool(payload.get("hosting")),
    }


def normalize_ip_api(payload: dict) -> IpGeo:
    if payload.get("status") != "success":
        return IpGeo(ip=payload.get("query"), ip_version=_ip_version(payload.get("query")))
    ip = payload.get("query")
    return IpGeo(
        ip=ip,
        ip_version=_ip_version(ip),
        reverse_dns=payload.get("reverse") or None,
        asn=_as_number(payload.get("as")),
        as_name=_as_label(payload.get("as")),
        org=payload.get("org") or payload.get("isp") or None,
        country=payload.get("country"),
        country_code=payload.get("countryCode"),
        city=payload.get("city"),
        lat=payload.get("lat"),
        lon=payload.get("lon"),
        timezone=payload.get("timezone"),
        ip_type=classify_ip_type(
            bool(payload.get("mobile")), bool(payload.get("proxy")), bool(payload.get("hosting")), True
        ),
        sources={"provider": "ip-api"},
    )


def normalize_freeipapi(payload: dict) -> IpGeo:
    ip = payload.get("ipAddress")
    return IpGeo(
        ip=ip,
        ip_version=payload.get("ipVersion") or _ip_version(ip),
        asn=_as_number(payload.get("asn")),
        org=payload.get("asnOrganization") or None,
        country=payload.get("countryName"),
        country_code=payload.get("countryCode"),
        city=payload.get("cityName"),
        lat=payload.get("latitude"),
        lon=payload.get("longitude"),
        ip_type=classify_ip_type(False, bool(payload.get("isProxy")), False, True),
        sources={"provider": "freeipapi"},
    )


def normalize_ipinfo(payload: dict) -> IpGeo:
    lat = lon = None
    loc = payload.get("loc")
    if isinstance(loc, str) and "," in loc:
        raw_lat, _, raw_lon = loc.partition(",")
        try:
            lat, lon = float(raw_lat), float(raw_lon)
        except ValueError:
            lat = lon = None
    ip = payload.get("ip")
    return IpGeo(
        ip=ip,
        ip_version=_ip_version(ip),
        reverse_dns=payload.get("hostname") or None,
        asn=_as_number(payload.get("org")),
        as_name=_as_label(payload.get("org")),
        org=_as_label(payload.get("org")),
        country_code=payload.get("country"),
        city=payload.get("city"),
        lat=lat,
        lon=lon,
        timezone=payload.get("timezone"),
        sources={"provider": "ipinfo"},
    )


def normalize_ipwhois(payload: dict) -> IpGeo:
    if not payload.get("success", True):
        return IpGeo(ip=payload.get("ip"))
    connection = payload.get("connection") or {}
    timezone = payload.get("timezone") or {}
    ip = payload.get("ip")
    return IpGeo(
        ip=ip,
        ip_version=_ip_version(ip),
        asn=_as_number(connection.get("asn")),
        as_name=connection.get("isp") or None,
        org=connection.get("org") or None,
        country=payload.get("country"),
        country_code=payload.get("country_code"),
        city=payload.get("city"),
        lat=payload.get("latitude"),
        lon=payload.get("longitude"),
        timezone=timezone.get("id") if isinstance(timezone, dict) else timezone,
        sources={"provider": "ipwho.is"},
    )


def normalize_ripestat_network_info(payload: dict) -> IpGeo:
    data = payload.get("data") or {}
    asns = data.get("asns") or []
    return IpGeo(asn=_as_number(asns[0]) if asns else None, sources={"asn": "ripestat"})


def parse_cf_trace(text: str) -> CfTrace:
    raw: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        raw[key.strip()] = value.strip()
    return CfTrace(
        ip=raw.get("ip"),
        colo=raw.get("colo"),
        loc=raw.get("loc"),
        warp=raw.get("warp"),
        gateway=raw.get("gateway"),
        rbi=raw.get("rbi"),
        raw=raw,
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_ip_geo_normalize.py -q`
Expected: PASS, 17 tests.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/ip_geo.py tests/test_ip_geo_normalize.py tests/fixtures/api
git commit -m "ip_geo: per-provider normalizers to a common IpGeo shape"
```

---

### Task 18: `ip_geo.py` — merge, dual-stack comparison and the live chain

**Files:**
- Modify: `src/netcheck/ip_geo.py` (append)
- Test: `tests/test_ip_geo_normalize.py` (append)

**Interfaces:**
- Consumes: Task 17's normalizers; `httpx.AsyncClient`; `Providers` config (Task 5).
- Produces:
  - `merge_geo(candidates: list[tuple[str, IpGeo]]) -> IpGeo`
  - `dual_stack_mismatch(v4: IpGeo | None, v6: IpGeo | None) -> str | None`
  - `async gather_identity(client, providers, ip: str | None = None, ipinfo_token: str | None = None) -> tuple[IpGeo, CfTrace | None, dict[str, bool], dict[str, object]]` — glue

**Testing note:** the live six-provider fan-out is glue — it issues real HTTP and its only logic is "call them all, keep whatever answered". It is not unit tested. The *merge* it feeds and the dual-stack comparison are pure and are tested here; end-to-end behaviour is covered by the manual smoke test in Task 40.

- [ ] **Step 1: Write the failing test (append to `tests/test_ip_geo_normalize.py`)**

```python
from netcheck.models import IpGeo
from netcheck.ip_geo import dual_stack_mismatch, merge_geo


def test_merge_takes_the_first_non_empty_value_in_priority_order():
    merged = merge_geo(
        [
            ("cf-trace", IpGeo(ip="203.0.113.44")),
            ("ip-api", IpGeo(asn="AS64500", city="Amsterdam", country_code="NL")),
            ("ipwho.is", IpGeo(asn="AS64999", city="Rotterdam", timezone="Europe/Amsterdam")),
        ]
    )
    assert merged.ip == "203.0.113.44"
    assert merged.asn == "AS64500"
    assert merged.city == "Amsterdam"
    assert merged.timezone == "Europe/Amsterdam"


def test_merge_records_which_provider_supplied_each_field():
    merged = merge_geo(
        [
            ("cf-trace", IpGeo(ip="203.0.113.44")),
            ("ip-api", IpGeo(asn="AS64500")),
            ("ipwho.is", IpGeo(timezone="Europe/Amsterdam")),
        ]
    )
    assert merged.sources["ip"] == "cf-trace"
    assert merged.sources["asn"] == "ip-api"
    assert merged.sources["timezone"] == "ipwho.is"


def test_merge_prefers_a_known_ip_type_over_unknown():
    merged = merge_geo([("a", IpGeo(ip_type="unknown")), ("b", IpGeo(ip_type="mobile"))])
    assert merged.ip_type == "mobile"
    assert merged.sources["ip_type"] == "b"


def test_merge_of_nothing_is_an_empty_geo():
    merged = merge_geo([])
    assert merged.ip is None
    assert merged.ip_type == "unknown"
    assert merged.sources == {}


def test_merge_ignores_a_provider_that_returned_nothing():
    merged = merge_geo([("dead", IpGeo()), ("live", IpGeo(asn="AS64500"))])
    assert merged.asn == "AS64500"
    assert merged.sources["asn"] == "live"


def test_dual_stack_mismatch_is_reported_not_resolved():
    v4 = IpGeo(ip="203.0.113.44", asn="AS64500", country_code="NL")
    v6 = IpGeo(ip="2001:db8::1", asn="AS64777", country_code="DE")
    note = dual_stack_mismatch(v4, v6)
    assert note is not None
    assert "AS64500" in note
    assert "AS64777" in note


def test_dual_stack_agreement_produces_no_note():
    v4 = IpGeo(ip="203.0.113.44", asn="AS64500", country_code="NL")
    v6 = IpGeo(ip="2001:db8::1", asn="AS64500", country_code="NL")
    assert dual_stack_mismatch(v4, v6) is None


def test_dual_stack_comparison_needs_both_sides():
    assert dual_stack_mismatch(IpGeo(asn="AS64500"), None) is None
    assert dual_stack_mismatch(None, IpGeo(asn="AS64500")) is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_ip_geo_normalize.py -q -k "merge or dual_stack"`
Expected: FAIL — `ImportError: cannot import name 'merge_geo'`.

- [ ] **Step 3: Append the merge logic to `src/netcheck/ip_geo.py`**

```python
from dataclasses import fields as dataclass_fields

_MERGE_SKIP = {"sources", "ip_type"}


def merge_geo(candidates: list[tuple[str, IpGeo]]) -> IpGeo:
    merged = IpGeo()
    sources: dict[str, str] = {}
    for name, geo in candidates:
        for f in dataclass_fields(IpGeo):
            if f.name in _MERGE_SKIP:
                continue
            if getattr(merged, f.name) is not None:
                continue
            value = getattr(geo, f.name)
            if value in (None, ""):
                continue
            setattr(merged, f.name, value)
            sources[f.name] = name
        if merged.ip_type == "unknown" and geo.ip_type != "unknown":
            merged.ip_type = geo.ip_type
            sources["ip_type"] = name
    merged.sources = sources
    return merged


def dual_stack_mismatch(v4: IpGeo | None, v6: IpGeo | None) -> str | None:
    if v4 is None or v6 is None or not v4.asn or not v6.asn:
        return None
    if v4.asn == v6.asn and (v4.country_code or "") == (v6.country_code or ""):
        return None
    return (
        f"IPv4 egress {v4.ip} is {v4.asn} ({v4.country_code}) but IPv6 egress {v6.ip} "
        f"is {v6.asn} ({v6.country_code}); the two stacks leave through different networks."
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_ip_geo_normalize.py -q`
Expected: PASS, 25 tests.

- [ ] **Step 5: Append the live provider chain (glue) to `src/netcheck/ip_geo.py`**

```python
import asyncio

import httpx

from netcheck.config import Providers


async def _json(client: httpx.AsyncClient, url: str, **kwargs) -> dict:
    response = await client.get(url, **kwargs)
    response.raise_for_status()
    return response.json()


async def _text(client: httpx.AsyncClient, url: str) -> str:
    response = await client.get(url)
    response.raise_for_status()
    return response.text


async def gather_identity(
    client: httpx.AsyncClient,
    providers: Providers,
    ip: str | None = None,
    ipinfo_token: str | None = None,
) -> tuple[IpGeo, CfTrace | None, dict[str, bool], dict[str, object]]:
    suffix = ip or ""
    headers = {"Authorization": f"Bearer {ipinfo_token}"} if ipinfo_token else {}
    calls = {
        "cf-trace": _text(client, providers.cf_trace_url),
        "ip-api": _json(client, f"{providers.ip_api_url}{suffix}"),
        "freeipapi": _json(client, f"{providers.freeipapi_url}{suffix}"),
        "ipinfo": _json(client, f"{providers.ipinfo_url}{suffix}json", headers=headers),
        "ipwho.is": _json(client, f"{providers.ipwhois_url}{suffix}"),
    }
    settled = await asyncio.gather(*calls.values(), return_exceptions=True)
    payloads = dict(zip(calls.keys(), settled))

    raw: dict[str, object] = {k: v for k, v in payloads.items() if not isinstance(v, BaseException)}
    cf = parse_cf_trace(payloads["cf-trace"]) if isinstance(payloads["cf-trace"], str) else None
    flags = provider_flags(payloads["ip-api"]) if isinstance(payloads["ip-api"], dict) else {}

    candidates: list[tuple[str, IpGeo]] = []
    if cf:
        candidates.append(("cf-trace", IpGeo(ip=cf.ip, country_code=cf.loc, sources={})))
    for name, normalizer in (
        ("ip-api", normalize_ip_api),
        ("freeipapi", normalize_freeipapi),
        ("ipinfo", normalize_ipinfo),
        ("ipwho.is", normalize_ipwhois),
    ):
        payload = payloads[name]
        if isinstance(payload, dict):
            candidates.append((name, normalizer(payload)))

    merged = merge_geo(candidates)
    if merged.ip:
        try:
            network_info = await _json(
                client, f"{providers.ripestat_base_url}/network-info/data.json", params={"resource": merged.ip}
            )
        except (httpx.HTTPError, ValueError):
            network_info = None
        if network_info:
            raw["ripestat-network-info"] = network_info
            authoritative = normalize_ripestat_network_info(network_info)
            if authoritative.asn:
                merged.asn = authoritative.asn
                merged.sources["asn"] = "ripestat"
    return merged, cf, flags, raw
```

RIPEstat overrides the ASN after the merge because it is the authoritative source for prefix-to-ASN, while the geo providers are best-effort (spec §6).

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/ip_geo.py tests/test_ip_geo_normalize.py
git commit -m "ip_geo: field-wise merge, dual-stack comparison, provider fan-out"
```

---

### Task 19: `bgp.py` — RIPEstat client with bounded bulk calls

**Files:**
- Create: `src/netcheck/bgp.py`
- Create: `tests/fixtures/api/ripestat_as_overview.json`, `tests/fixtures/api/ripestat_asn_neighbours.json`, `tests/fixtures/api/ripestat_announced_prefixes.json`, `tests/fixtures/api/ripestat_bgp_updates.json`
- Test: `tests/test_bgp.py`

**Interfaces:**
- Consumes: `BgpEvent`, `IxpPresence`, `BgpIntel` (Task 4); `Providers` (Task 5).
- Produces:
  - `parse_as_overview(payload: dict) -> dict[str, str | None]` — keys `holder`, `registry`, `allocated_at`
  - `parse_asn_neighbours(payload: dict) -> tuple[list[str], list[str], list[str]]` — `(upstreams, peers, downstreams)`
  - `parse_announced_prefixes(payload: dict) -> tuple[list[str], int, int]`
  - `parse_bgp_updates(payload: dict) -> list[BgpEvent]`
  - `classify_stability(events: list[BgpEvent], days: int) -> str`
  - `async ripestat(client, providers, call: str, resource: str, **extra) -> dict` — glue, but its query bounding is asserted in tests

- [ ] **Step 1: Create the RIPEstat fixtures**

`tests/fixtures/api/ripestat_as_overview.json`:

```json
{
  "status": "ok",
  "data_call_name": "as-overview",
  "data": {
    "resource": "64500",
    "holder": "EXAMPLE-AS Example Telecom BV",
    "announced": true,
    "block": {
      "resource": "64496-64511",
      "desc": "Reserved for use in documentation",
      "name": "IANA 16-bit Autonomous System Number Block"
    },
    "type": "as"
  }
}
```

`tests/fixtures/api/ripestat_asn_neighbours.json`:

```json
{
  "status": "ok",
  "data_call_name": "asn-neighbours",
  "data": {
    "neighbours": [
      { "asn": 3356, "type": "left", "power": 3, "v4_peers": 12, "v6_peers": 4 },
      { "asn": 1299, "type": "left", "power": 2, "v4_peers": 8, "v6_peers": 3 },
      { "asn": 6939, "type": "right", "power": 1, "v4_peers": 2, "v6_peers": 1 },
      { "asn": 64501, "type": "right", "power": 1, "v4_peers": 1, "v6_peers": 0 },
      { "asn": 8075, "type": "unknown", "power": 1, "v4_peers": 1, "v6_peers": 1 }
    ]
  }
}
```

`tests/fixtures/api/ripestat_announced_prefixes.json`:

```json
{
  "status": "ok",
  "data_call_name": "announced-prefixes",
  "data": {
    "prefixes": [
      { "prefix": "203.0.113.0/24", "timelines": [] },
      { "prefix": "198.51.100.0/24", "timelines": [] },
      { "prefix": "2001:db8::/32", "timelines": [] }
    ]
  }
}
```

`tests/fixtures/api/ripestat_bgp_updates.json`:

```json
{
  "status": "ok",
  "data_call_name": "bgp-updates",
  "data": {
    "updates": [
      { "timestamp": "2026-08-01T04:00:00", "type": "A", "attrs": { "target_prefix": "203.0.113.0/24", "path": [3356, 64500] } },
      { "timestamp": "2026-08-01T04:05:00", "type": "W", "attrs": { "target_prefix": "203.0.113.0/24" } },
      { "timestamp": "2026-08-01T04:06:00", "type": "A", "attrs": { "target_prefix": "203.0.113.0/24", "path": [1299, 64500] } }
    ],
    "nr_updates": 3
  }
}
```

- [ ] **Step 2: Write the failing test**

`tests/test_bgp.py`:

```python
from __future__ import annotations

import httpx
import pytest

from netcheck.bgp import (
    classify_stability,
    parse_announced_prefixes,
    parse_as_overview,
    parse_asn_neighbours,
    parse_bgp_updates,
    ripestat,
)
from netcheck.config import Providers
from netcheck.models import BgpEvent


def test_as_overview_extracts_holder_and_block(api_fixture):
    info = parse_as_overview(api_fixture("ripestat_as_overview.json"))
    assert info["holder"] == "EXAMPLE-AS Example Telecom BV"
    assert info["registry"] == "IANA 16-bit Autonomous System Number Block"


def test_as_overview_of_an_error_payload_is_empty():
    assert parse_as_overview({"status": "error", "data": {}}) == {
        "holder": None,
        "registry": None,
        "allocated_at": None,
    }


def test_neighbours_split_into_upstreams_peers_and_downstreams(api_fixture):
    upstreams, peers, downstreams = parse_asn_neighbours(api_fixture("ripestat_asn_neighbours.json"))
    assert upstreams == ["AS3356", "AS1299"]
    assert downstreams == ["AS6939", "AS64501"]
    assert peers == ["AS8075"]


def test_announced_prefixes_are_counted_by_family(api_fixture):
    prefixes, v4, v6 = parse_announced_prefixes(api_fixture("ripestat_announced_prefixes.json"))
    assert prefixes == ["203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"]
    assert v4 == 2
    assert v6 == 1


def test_announced_prefixes_of_an_empty_payload():
    assert parse_announced_prefixes({"data": {}}) == ([], 0, 0)


def test_bgp_updates_become_typed_events(api_fixture):
    events = parse_bgp_updates(api_fixture("ripestat_bgp_updates.json"))
    assert len(events) == 3
    assert events[0].type == "A"
    assert events[0].prefix == "203.0.113.0/24"
    assert events[0].path == [3356, 64500]
    assert events[1].type == "W"
    assert events[1].path == []


def test_stability_of_a_quiet_asn_is_stable():
    assert classify_stability([], days=14) == "stable"


def test_stability_of_a_flapping_asn_is_unstable():
    events = [BgpEvent(timestamp="2026-08-01T00:00:00", type="W", prefix="203.0.113.0/24") for _ in range(60)]
    assert classify_stability(events, days=14) == "unstable"


def test_stability_only_counts_withdrawals_not_announcements():
    events = [BgpEvent(timestamp="2026-08-01T00:00:00", type="A", prefix="203.0.113.0/24") for _ in range(200)]
    assert classify_stability(events, days=14) == "stable"


def test_stability_is_unknown_without_a_timeframe():
    assert classify_stability([BgpEvent(timestamp="x", type="W")], days=0) == "unknown"


async def test_ripestat_bounds_bulk_calls_with_max_rows_and_a_timeframe(httpx_mock):
    httpx_mock.add_response(json={"status": "ok", "data": {}})
    providers = Providers(ripestat_max_rows=25, ripestat_timeframe_days=7)
    async with httpx.AsyncClient() as client:
        await ripestat(client, providers, "bgp-updates", "AS64500")
    request = httpx_mock.get_request()
    assert request.url.params["resource"] == "AS64500"
    assert request.url.params["max_rows"] == "25"
    assert "starttime" in request.url.params
    assert request.url.path.endswith("/bgp-updates/data.json")


async def test_ripestat_does_not_bound_non_bulk_calls(httpx_mock):
    httpx_mock.add_response(json={"status": "ok", "data": {}})
    async with httpx.AsyncClient() as client:
        await ripestat(client, Providers(), "as-overview", "AS64500")
    request = httpx_mock.get_request()
    assert "max_rows" not in request.url.params
    assert "starttime" not in request.url.params
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_bgp.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.bgp'`.

- [ ] **Step 4: Implement `src/netcheck/bgp.py`**

```python
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import httpx

from netcheck.config import Providers
from netcheck.models import BgpEvent

# These calls return the whole routing history of an ASN; on a large ISP that is
# tens of megabytes unless the window and row count are pinned.
BULK_CALLS = {"bgp-updates", "routing-history", "bgplay", "announced-prefixes"}

_UNSTABLE_WITHDRAWALS_PER_DAY = 3.0


def _as_label(asn: object) -> str:
    text = str(asn).upper()
    return text if text.startswith("AS") else f"AS{text}"


def parse_as_overview(payload: dict) -> dict[str, str | None]:
    data = payload.get("data") or {}
    block = data.get("block") or {}
    return {
        "holder": data.get("holder") or None,
        "registry": block.get("name") or None,
        "allocated_at": data.get("announced_since") or None,
    }


def parse_asn_neighbours(payload: dict) -> tuple[list[str], list[str], list[str]]:
    upstreams: list[str] = []
    peers: list[str] = []
    downstreams: list[str] = []
    for neighbour in (payload.get("data") or {}).get("neighbours") or []:
        label = _as_label(neighbour.get("asn"))
        kind = neighbour.get("type")
        if kind == "left":
            upstreams.append(label)
        elif kind == "right":
            downstreams.append(label)
        else:
            peers.append(label)
    return upstreams, peers, downstreams


def parse_announced_prefixes(payload: dict) -> tuple[list[str], int, int]:
    prefixes: list[str] = []
    v4 = v6 = 0
    for entry in (payload.get("data") or {}).get("prefixes") or []:
        prefix = entry.get("prefix")
        if not prefix:
            continue
        prefixes.append(prefix)
        try:
            version = ipaddress.ip_network(prefix, strict=False).version
        except ValueError:
            continue
        if version == 4:
            v4 += 1
        else:
            v6 += 1
    return prefixes, v4, v6


def parse_bgp_updates(payload: dict) -> list[BgpEvent]:
    events: list[BgpEvent] = []
    for update in (payload.get("data") or {}).get("updates") or []:
        attrs = update.get("attrs") or {}
        events.append(
            BgpEvent(
                timestamp=update.get("timestamp", ""),
                type=update.get("type", ""),
                prefix=attrs.get("target_prefix"),
                path=[int(hop) for hop in attrs.get("path") or []],
            )
        )
    return events


def classify_stability(events: list[BgpEvent], days: int) -> str:
    if days <= 0:
        return "unknown"
    withdrawals = sum(1 for e in events if e.type == "W")
    return "unstable" if withdrawals / days >= _UNSTABLE_WITHDRAWALS_PER_DAY else "stable"


async def ripestat(
    client: httpx.AsyncClient,
    providers: Providers,
    call: str,
    resource: str,
    **extra: str,
) -> dict:
    params: dict[str, str] = {"resource": resource, **extra}
    if call in BULK_CALLS:
        start = datetime.now(timezone.utc) - timedelta(days=providers.ripestat_timeframe_days)
        params["max_rows"] = str(providers.ripestat_max_rows)
        params["starttime"] = start.strftime("%Y-%m-%dT%H:%M:%S")
    response = await client.get(f"{providers.ripestat_base_url}/{call}/data.json", params=params)
    response.raise_for_status()
    return response.json()
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_bgp.py -q`
Expected: PASS, 12 tests.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/bgp.py tests/test_bgp.py tests/fixtures/api
git commit -m "bgp: ripestat parsers and bounded bulk queries"
```

---

### Task 20: `bgp.py` — ASRank, Team Cymru and cached PeeringDB

**Files:**
- Modify: `src/netcheck/bgp.py` (append)
- Create: `tests/fixtures/api/asrank.json`, `tests/fixtures/api/peeringdb_net.json`, `tests/fixtures/api/peeringdb_netixlan.json`
- Test: `tests/test_bgp.py` (append)

**Interfaces:**
- Consumes: Task 19's helpers; `IxpPresence` (Task 4).
- Produces:
  - `parse_asrank(payload: dict) -> tuple[int | None, int | None, int | None]` — `(rank, cone_asns, cone_prefixes)`
  - `parse_cymru_origin(txt_record: str) -> dict[str, str]`
  - `parse_peeringdb_net(payload: dict) -> tuple[str | None, str | None, int | None]` — `(info_type, info_traffic, net_id)`
  - `parse_peeringdb_netixlan(payload: dict) -> list[IxpPresence]`
  - `async cached_json(cache_dir: Path, key: str, ttl_hours: int, fetch) -> dict` — disk cache used for PeeringDB

- [ ] **Step 1: Create the fixtures**

`tests/fixtures/api/asrank.json`:

```json
{
  "data": {
    "asn": {
      "asn": "64500",
      "rank": 1842,
      "asnName": "EXAMPLE-AS",
      "organization": { "orgName": "Example Telecom BV" },
      "cone": { "numberAsns": 37, "numberPrefixes": 412, "numberAddresses": 1048576 },
      "asnDegree": { "provider": 2, "peer": 1, "customer": 4, "total": 7 }
    }
  }
}
```

`tests/fixtures/api/peeringdb_net.json`:

```json
{
  "data": [
    {
      "id": 4242,
      "asn": 64500,
      "name": "Example Telecom",
      "info_type": "Cable/DSL/ISP",
      "info_traffic": "100-200Gbps",
      "info_scope": "Regional",
      "policy_general": "Open"
    }
  ]
}
```

`tests/fixtures/api/peeringdb_netixlan.json`:

```json
{
  "data": [
    { "id": 1, "net_id": 4242, "name": "AMS-IX", "city": "Amsterdam", "country": "NL", "speed": 100000, "operational": true },
    { "id": 2, "net_id": 4242, "name": "DE-CIX Frankfurt", "city": "Frankfurt", "country": "DE", "speed": 200000, "operational": true },
    { "id": 3, "net_id": 4242, "name": "Dead-IX", "city": "Nowhere", "country": "NL", "speed": 1000, "operational": false }
  ]
}
```

- [ ] **Step 2: Write the failing test (append to `tests/test_bgp.py`)**

```python
import json
from pathlib import Path

from netcheck.bgp import (
    cached_json,
    parse_asrank,
    parse_cymru_origin,
    parse_peeringdb_net,
    parse_peeringdb_netixlan,
)


def test_asrank_gives_rank_and_customer_cone(api_fixture):
    rank, cone_asns, cone_prefixes = parse_asrank(api_fixture("asrank.json"))
    assert rank == 1842
    assert cone_asns == 37
    assert cone_prefixes == 412


def test_asrank_of_an_unknown_asn_is_all_none():
    assert parse_asrank({"data": {"asn": None}}) == (None, None, None)


def test_cymru_origin_txt_is_split_into_fields():
    record = "64500 | 203.0.113.0/24 | NL | ripencc | 2001-05-21"
    assert parse_cymru_origin(record) == {
        "asn": "AS64500",
        "prefix": "203.0.113.0/24",
        "country": "NL",
        "registry": "ripencc",
        "allocated_at": "2001-05-21",
    }


def test_cymru_origin_with_multiple_origin_asns_takes_the_first():
    record = "64500 64501 | 203.0.113.0/24 | NL | ripencc | 2001-05-21"
    assert parse_cymru_origin(record)["asn"] == "AS64500"


def test_cymru_origin_of_garbage_is_empty():
    assert parse_cymru_origin("no such name") == {}


def test_peeringdb_net_gives_info_type_traffic_and_id(api_fixture):
    info_type, traffic, net_id = parse_peeringdb_net(api_fixture("peeringdb_net.json"))
    assert info_type == "Cable/DSL/ISP"
    assert traffic == "100-200Gbps"
    assert net_id == 4242


def test_peeringdb_net_of_an_unlisted_asn_is_all_none():
    assert parse_peeringdb_net({"data": []}) == (None, None, None)


def test_peeringdb_netixlan_lists_only_operational_exchanges(api_fixture):
    ixps = parse_peeringdb_netixlan(api_fixture("peeringdb_netixlan.json"))
    assert [i.name for i in ixps] == ["AMS-IX", "DE-CIX Frankfurt"]
    assert ixps[0].country == "NL"
    assert ixps[1].speed_mbps == 200000


async def test_cached_json_writes_then_reuses_the_cache(tmp_path: Path):
    calls = []

    async def fetch() -> dict:
        calls.append(1)
        return {"value": len(calls)}

    first = await cached_json(tmp_path, "peeringdb-net-64500", ttl_hours=24, fetch=fetch)
    second = await cached_json(tmp_path, "peeringdb-net-64500", ttl_hours=24, fetch=fetch)
    assert first == {"value": 1}
    assert second == {"value": 1}
    assert len(calls) == 1
    assert json.loads((tmp_path / "peeringdb-net-64500.json").read_text(encoding="utf-8"))["value"] == 1


async def test_cached_json_refetches_once_the_entry_expires(tmp_path: Path):
    calls = []

    async def fetch() -> dict:
        calls.append(1)
        return {"value": len(calls)}

    await cached_json(tmp_path, "k", ttl_hours=24, fetch=fetch)
    result = await cached_json(tmp_path, "k", ttl_hours=0, fetch=fetch)
    assert result == {"value": 2}
    assert len(calls) == 2


async def test_cached_json_survives_a_corrupt_cache_file(tmp_path: Path):
    (tmp_path / "k.json").write_text("{not json", encoding="utf-8")

    async def fetch() -> dict:
        return {"value": "fresh"}

    assert await cached_json(tmp_path, "k", ttl_hours=24, fetch=fetch) == {"value": "fresh"}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_bgp.py -q -k "asrank or cymru or peeringdb or cached"`
Expected: FAIL — `ImportError: cannot import name 'cached_json'`.

- [ ] **Step 4: Append to `src/netcheck/bgp.py`**

```python
import json
import os
import time
from pathlib import Path
from typing import Awaitable, Callable

from netcheck.models import IxpPresence


def parse_asrank(payload: dict) -> tuple[int | None, int | None, int | None]:
    asn = ((payload.get("data") or {}).get("asn")) or {}
    cone = asn.get("cone") or {}
    return asn.get("rank"), cone.get("numberAsns"), cone.get("numberPrefixes")


def parse_cymru_origin(txt_record: str) -> dict[str, str]:
    parts = [part.strip() for part in txt_record.split("|")]
    if len(parts) < 5:
        return {}
    return {
        "asn": _as_label(parts[0].split()[0]),
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated_at": parts[4],
    }


def parse_peeringdb_net(payload: dict) -> tuple[str | None, str | None, int | None]:
    rows = payload.get("data") or []
    if not rows:
        return None, None, None
    row = rows[0]
    return row.get("info_type") or None, row.get("info_traffic") or None, row.get("id")


def parse_peeringdb_netixlan(payload: dict) -> list[IxpPresence]:
    return [
        IxpPresence(
            name=row.get("name", ""),
            city=row.get("city"),
            country=row.get("country"),
            speed_mbps=row.get("speed"),
        )
        for row in payload.get("data") or []
        if row.get("operational")
    ]


async def cached_json(
    cache_dir: Path,
    key: str,
    ttl_hours: int,
    fetch: Callable[[], Awaitable[dict]],
) -> dict:
    path = Path(cache_dir) / f"{key}.json"
    if path.exists() and (time.time() - path.stat().st_mtime) < ttl_hours * 3600:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    payload = await fetch()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)
    return payload
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_bgp.py -q`
Expected: PASS, 23 tests.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/bgp.py tests/test_bgp.py tests/fixtures/api
git commit -m "bgp: asrank, team cymru and disk-cached peeringdb parsing"
```

---

### Task 21: `bgp.py` — assemble `BgpIntel`

**Files:**
- Modify: `src/netcheck/bgp.py` (append)
- Test: `tests/test_bgp.py` (append)

**Interfaces:**
- Consumes: every parser from Tasks 19–20.
- Produces:
  - `build_bgp_intel(asn: str, overview: dict, neighbours: dict, prefixes: dict, updates: dict, asrank: dict | None, pdb_net: dict | None, pdb_ixlan: dict | None, timeframe_days: int) -> BgpIntel`
  - `async collect_bgp(client, providers, cache_dir, asn, peeringdb_key=None) -> tuple[BgpIntel, dict[str, object]]` — glue

- [ ] **Step 1: Write the failing test (append to `tests/test_bgp.py`)**

```python
from netcheck.bgp import build_bgp_intel


def test_build_bgp_intel_merges_every_source(api_fixture):
    intel = build_bgp_intel(
        asn="AS64500",
        overview=api_fixture("ripestat_as_overview.json"),
        neighbours=api_fixture("ripestat_asn_neighbours.json"),
        prefixes=api_fixture("ripestat_announced_prefixes.json"),
        updates=api_fixture("ripestat_bgp_updates.json"),
        asrank=api_fixture("asrank.json"),
        pdb_net=api_fixture("peeringdb_net.json"),
        pdb_ixlan=api_fixture("peeringdb_netixlan.json"),
        timeframe_days=14,
    )
    assert intel.asn == "AS64500"
    assert intel.holder == "EXAMPLE-AS Example Telecom BV"
    assert intel.upstreams == ["AS3356", "AS1299"]
    assert intel.prefix_count_v4 == 2
    assert intel.prefix_count_v6 == 1
    assert intel.stability == "stable"
    assert intel.asrank == 1842
    assert intel.cone_asns == 37
    assert intel.pdb_info_type == "Cable/DSL/ISP"
    assert [i.name for i in intel.ixps] == ["AMS-IX", "DE-CIX Frankfurt"]
    assert len(intel.flaps) == 3


def test_build_bgp_intel_tolerates_every_optional_source_being_absent(api_fixture):
    intel = build_bgp_intel(
        asn="AS64500",
        overview=api_fixture("ripestat_as_overview.json"),
        neighbours={},
        prefixes={},
        updates={},
        asrank=None,
        pdb_net=None,
        pdb_ixlan=None,
        timeframe_days=14,
    )
    assert intel.asn == "AS64500"
    assert intel.upstreams == []
    assert intel.asrank is None
    assert intel.pdb_info_type is None
    assert intel.ixps == []
    assert intel.stability == "stable"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_bgp.py -q -k build_bgp_intel`
Expected: FAIL — `ImportError: cannot import name 'build_bgp_intel'`.

- [ ] **Step 3: Append to `src/netcheck/bgp.py`**

```python
from netcheck.models import BgpIntel


def build_bgp_intel(
    asn: str,
    overview: dict,
    neighbours: dict,
    prefixes: dict,
    updates: dict,
    asrank: dict | None,
    pdb_net: dict | None,
    pdb_ixlan: dict | None,
    timeframe_days: int,
) -> BgpIntel:
    info = parse_as_overview(overview)
    upstreams, peers, downstreams = parse_asn_neighbours(neighbours)
    announced, v4, v6 = parse_announced_prefixes(prefixes)
    events = parse_bgp_updates(updates)
    rank, cone_asns, cone_prefixes = parse_asrank(asrank) if asrank else (None, None, None)
    info_type, traffic, _net_id = parse_peeringdb_net(pdb_net) if pdb_net else (None, None, None)
    return BgpIntel(
        asn=asn,
        holder=info["holder"],
        registry=info["registry"],
        allocated_at=info["allocated_at"],
        upstreams=upstreams,
        peers=peers,
        downstreams=downstreams,
        announced_prefixes=announced,
        prefix_count_v4=v4,
        prefix_count_v6=v6,
        flaps=events,
        stability=classify_stability(events, timeframe_days),
        ixps=parse_peeringdb_netixlan(pdb_ixlan) if pdb_ixlan else [],
        pdb_info_type=info_type,
        pdb_traffic=traffic,
        asrank=rank,
        cone_asns=cone_asns,
        cone_prefixes=cone_prefixes,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_bgp.py -q`
Expected: PASS, 25 tests.

- [ ] **Step 5: Append the collection glue to `src/netcheck/bgp.py`**

```python
import asyncio

_ASRANK_QUERY = """
query ASN($asn: String!) {
  asn(asn: $asn) {
    asn
    rank
    asnName
    organization { orgName }
    cone { numberAsns numberPrefixes numberAddresses }
    asnDegree { provider peer customer total }
  }
}
"""


async def collect_bgp(
    client: httpx.AsyncClient,
    providers: Providers,
    cache_dir: Path,
    asn: str,
    peeringdb_key: str | None = None,
) -> tuple[BgpIntel, dict[str, object]]:
    number = asn.upper().removeprefix("AS")

    async def _asrank() -> dict:
        response = await client.post(
            providers.asrank_url, json={"query": _ASRANK_QUERY, "variables": {"asn": number}}
        )
        response.raise_for_status()
        return response.json()

    async def _pdb(endpoint: str, **params) -> dict:
        headers = {"Authorization": f"Api-Key {peeringdb_key}"} if peeringdb_key else {}
        response = await client.get(
            f"{providers.peeringdb_base_url}/{endpoint}", params=params, headers=headers
        )
        response.raise_for_status()
        return response.json()

    settled = await asyncio.gather(
        ripestat(client, providers, "as-overview", asn),
        ripestat(client, providers, "asn-neighbours", asn),
        ripestat(client, providers, "announced-prefixes", asn),
        ripestat(client, providers, "bgp-updates", asn),
        _asrank(),
        cached_json(cache_dir, f"pdb-net-{number}", providers.peeringdb_cache_hours, lambda: _pdb("net", asn=number)),
        return_exceptions=True,
    )
    overview, neighbours, prefixes, updates, asrank, pdb_net = [
        None if isinstance(item, BaseException) else item for item in settled
    ]

    pdb_ixlan = None
    if pdb_net:
        _, _, net_id = parse_peeringdb_net(pdb_net)
        if net_id:
            try:
                pdb_ixlan = await cached_json(
                    cache_dir,
                    f"pdb-netixlan-{net_id}",
                    providers.peeringdb_cache_hours,
                    lambda: _pdb("netixlan", net_id=net_id),
                )
            except httpx.HTTPError:
                pdb_ixlan = None

    intel = build_bgp_intel(
        asn=asn,
        overview=overview or {},
        neighbours=neighbours or {},
        prefixes=prefixes or {},
        updates=updates or {},
        asrank=asrank,
        pdb_net=pdb_net,
        pdb_ixlan=pdb_ixlan,
        timeframe_days=providers.ripestat_timeframe_days,
    )
    raw = {
        "ripestat-as-overview": overview,
        "ripestat-asn-neighbours": neighbours,
        "ripestat-announced-prefixes": prefixes,
        "ripestat-bgp-updates": updates,
        "caida-asrank": asrank,
        "peeringdb-net": pdb_net,
        "peeringdb-netixlan": pdb_ixlan,
    }
    return intel, {k: v for k, v in raw.items() if v is not None}
```

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/bgp.py tests/test_bgp.py
git commit -m "bgp: assemble BgpIntel from every source with per-source failures tolerated"
```

---

### Task 22: `reputation.py` — FireHOL netset cache and local lookup

**Files:**
- Create: `src/netcheck/reputation.py`
- Create: `tests/fixtures/api/firehol_sample.netset`
- Test: `tests/test_reputation.py`

**Interfaces:**
- Consumes: `Providers` config (Task 5).
- Produces:
  - `parse_netset(text: str) -> list[str]`
  - `NetsetIndex` with `add(name: str, cidrs: list[str]) -> None` and `hits(ip: str) -> list[str]`
  - `async refresh_netsets(client, providers, cache_dir: Path) -> NetsetIndex` — glue

- [ ] **Step 1: Create the netset fixture**

`tests/fixtures/api/firehol_sample.netset`:

```text
#
# firehol_level1
#
# Source: example
# Maintainer: FireHOL Team
#
0.0.0.0/8
10.0.0.0/8
198.51.100.0/24
203.0.113.44
2001:db8::/32

192.0.2.0/25
```

- [ ] **Step 2: Write the failing test**

`tests/test_reputation.py`:

```python
from __future__ import annotations

from netcheck.reputation import NetsetIndex, parse_netset


def test_parse_netset_strips_comments_and_blank_lines(fixtures_dir):
    cidrs = parse_netset((fixtures_dir / "api" / "firehol_sample.netset").read_text(encoding="utf-8"))
    assert cidrs == [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "198.51.100.0/24",
        "203.0.113.44",
        "2001:db8::/32",
        "192.0.2.0/25",
    ]


def test_parse_netset_of_an_empty_file_is_empty():
    assert parse_netset("# only a comment\n\n") == []


def test_index_matches_an_ip_inside_a_listed_prefix():
    index = NetsetIndex()
    index.add("firehol_level1", ["198.51.100.0/24"])
    assert index.hits("198.51.100.7") == ["firehol_level1"]


def test_index_does_not_match_an_ip_outside_every_prefix():
    index = NetsetIndex()
    index.add("firehol_level1", ["198.51.100.0/24"])
    assert index.hits("203.0.113.7") == []


def test_index_matches_a_bare_host_entry():
    index = NetsetIndex()
    index.add("abusers", ["203.0.113.44"])
    assert index.hits("203.0.113.44") == ["abusers"]
    assert index.hits("203.0.113.45") == []


def test_index_reports_every_list_an_ip_appears_on():
    index = NetsetIndex()
    index.add("level1", ["198.51.100.0/24"])
    index.add("level2", ["198.51.100.0/25"])
    index.add("clean", ["203.0.113.0/24"])
    assert sorted(index.hits("198.51.100.7")) == ["level1", "level2"]


def test_index_handles_ipv6_separately_from_ipv4():
    index = NetsetIndex()
    index.add("v6list", ["2001:db8::/32"])
    index.add("v4list", ["203.0.113.0/24"])
    assert index.hits("2001:db8::1") == ["v6list"]
    assert index.hits("203.0.113.1") == ["v4list"]


def test_index_ignores_malformed_entries_instead_of_raising():
    index = NetsetIndex()
    index.add("junk", ["not-an-ip", "999.1.1.1/24", "198.51.100.0/24"])
    assert index.hits("198.51.100.7") == ["junk"]


def test_index_lookup_of_a_malformed_ip_is_empty_not_an_error():
    index = NetsetIndex()
    index.add("level1", ["198.51.100.0/24"])
    assert index.hits("not-an-ip") == []


def test_index_built_from_the_real_fixture_matches_the_expected_entries(fixtures_dir):
    index = NetsetIndex()
    index.add(
        "firehol_level1",
        parse_netset((fixtures_dir / "api" / "firehol_sample.netset").read_text(encoding="utf-8")),
    )
    assert index.hits("10.1.2.3") == ["firehol_level1"]
    assert index.hits("192.0.2.10") == ["firehol_level1"]
    assert index.hits("192.0.2.200") == []
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_reputation.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.reputation'`.

- [ ] **Step 4: Implement the FireHOL half of `src/netcheck/reputation.py`**

```python
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
```

A netset download failure falls back to the cached copy if one exists and is simply skipped if not: a stale blocklist is far more useful than no reputation section.

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_reputation.py -q`
Expected: PASS, 10 tests.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/reputation.py tests/test_reputation.py tests/fixtures/api/firehol_sample.netset
git commit -m "reputation: firehol netset cache with local range index"
```

---

### Task 23: `reputation.py` — DNSBL decoding (Spamhaus `127.255.255.x` regression)

**Files:**
- Modify: `src/netcheck/reputation.py` (append)
- Test: `tests/test_dnsbl_decode.py`

**Interfaces:**
- Consumes: `DnsblHit` (Task 4).
- Produces:
  - `reverse_ip(ip: str) -> str`
  - `DnsblOutcome` dataclass: `zone: str, listed: bool, codes: list[str], unavailable_reason: str | None`
  - `decode_dnsbl(zone: str, answers: list[str]) -> DnsblOutcome`
  - `summarize_dnsbl(outcomes: list[DnsblOutcome]) -> tuple[list[DnsblHit], bool]` — `(hits, query_blocked)`

**This is the regression test for the false-positive bug found during design (spec §8).** Spamhaus answers `127.255.255.254` when the query came through a public resolver — which is true for anyone on 1.1.1.1 or 8.8.8.8 — and `127.255.255.255` when rate limited. Treating either as a listing red-flags most users. Both must decode to *result unavailable*, never to a hit.

- [ ] **Step 1: Write the failing test**

`tests/test_dnsbl_decode.py`:

```python
from __future__ import annotations

import pytest

from netcheck.reputation import decode_dnsbl, reverse_ip, summarize_dnsbl


def test_reverse_ip_builds_the_dnsbl_query_label():
    assert reverse_ip("203.0.113.44") == "44.113.0.203"
    assert reverse_ip("8.8.8.8") == "8.8.8.8"


def test_reverse_ip_rejects_ipv6_because_classic_dnsbls_are_v4_only():
    with pytest.raises(ValueError):
        reverse_ip("2001:db8::1")


def test_a_real_spamhaus_listing_is_reported_as_listed():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.0.0.2", "127.0.0.4"])
    assert outcome.listed is True
    assert outcome.unavailable_reason is None
    assert outcome.codes == ["127.0.0.2", "127.0.0.4"]


def test_public_resolver_error_code_is_not_a_listing():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.255.255.254"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "query_via_public_resolver"
    assert outcome.codes == ["127.255.255.254"]


def test_rate_limit_error_code_is_not_a_listing():
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.255.255.255"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "rate_limited"


@pytest.mark.parametrize(
    "code",
    ["127.255.255.252", "127.255.255.253", "127.255.255.0", "127.255.255.1"],
)
def test_every_other_code_in_the_error_range_is_a_provider_error_not_a_listing(code):
    outcome = decode_dnsbl("zen.spamhaus.org", [code])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "provider_error"


def test_an_error_code_mixed_with_a_listing_code_still_means_unavailable():
    # A response carrying an error code cannot be trusted for the listing bits.
    outcome = decode_dnsbl("zen.spamhaus.org", ["127.0.0.2", "127.255.255.254"])
    assert outcome.listed is False
    assert outcome.unavailable_reason == "query_via_public_resolver"


def test_no_answers_means_not_listed_and_no_error():
    outcome = decode_dnsbl("bl.spamcop.net", [])
    assert outcome.listed is False
    assert outcome.unavailable_reason is None
    assert outcome.codes == []


def test_a_non_loopback_answer_is_ignored_as_a_listing():
    outcome = decode_dnsbl("dnsbl.dronebl.org", ["10.0.0.1"])
    assert outcome.listed is False
    assert outcome.unavailable_reason is None


def test_summarize_returns_only_real_listings():
    outcomes = [
        decode_dnsbl("zen.spamhaus.org", ["127.255.255.254"]),
        decode_dnsbl("bl.spamcop.net", ["127.0.0.2"]),
        decode_dnsbl("b.barracudacentral.org", []),
    ]
    hits, blocked = summarize_dnsbl(outcomes)
    assert [h.zone for h in hits] == ["bl.spamcop.net"]
    assert hits[0].codes == ["127.0.0.2"]
    assert blocked is True


def test_summarize_reports_not_blocked_when_every_zone_answered_cleanly():
    outcomes = [
        decode_dnsbl("zen.spamhaus.org", []),
        decode_dnsbl("bl.spamcop.net", []),
    ]
    hits, blocked = summarize_dnsbl(outcomes)
    assert hits == []
    assert blocked is False
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_dnsbl_decode.py -q`
Expected: FAIL — `ImportError: cannot import name 'decode_dnsbl'`.

- [ ] **Step 3: Append the DNSBL decoder to `src/netcheck/reputation.py`**

```python
from dataclasses import dataclass, field

from netcheck.models import DnsblHit

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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_dnsbl_decode.py -q`
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/reputation.py tests/test_dnsbl_decode.py
git commit -m "reputation: decode dnsbl 127.255.255.x error range as unavailable"
```

---

### Task 24: `reputation.py` — InternetDB, captcha risk and assembly

**Files:**
- Modify: `src/netcheck/reputation.py` (append)
- Create: `tests/fixtures/api/internetdb.json`
- Test: `tests/test_reputation.py` (append)

**Interfaces:**
- Consumes: Tasks 22–23; `InternetDbResult`, `Reputation` (Task 4).
- Produces:
  - `normalize_internetdb(payload: dict) -> InternetDbResult`
  - `captcha_risk(firehol_hits: list[str], dnsbl_hits: list[DnsblHit], ip_type: str, abuseipdb_score: int | None) -> tuple[str, str]` — `(risk, rationale)`
  - `build_reputation(internetdb, firehol_hits, dnsbl_outcomes, ip_type, abuseipdb_score, abuseipdb_reports) -> Reputation`
  - `async query_dnsbl(ip: str, zones: list[str], timeout: float) -> list[DnsblOutcome]` — glue
  - `async fetch_internetdb(client, providers, ip: str) -> dict` — glue
  - `async fetch_abuseipdb(client, providers, ip: str, key: str) -> dict` — glue

These four pieces are assembled into a `Reputation` by `cli.py` (Task 37), which is the only place that knows whether `--dnsbl` was passed and whether an AbuseIPDB key exists.

- [ ] **Step 1: Create the InternetDB fixture**

`tests/fixtures/api/internetdb.json`:

```json
{
  "ip": "203.0.113.44",
  "ports": [22, 80, 443, 7547],
  "hostnames": ["host-203-0-113-44.example.net"],
  "cpes": ["cpe:/a:nginx:nginx:1.24.0"],
  "tags": ["cdn", "iot"],
  "vulns": ["CVE-2024-1234"]
}
```

- [ ] **Step 2: Write the failing test (append to `tests/test_reputation.py`)**

```python
from netcheck.reputation import (
    build_reputation,
    captcha_risk,
    decode_dnsbl,
    normalize_internetdb,
    summarize_dnsbl,
)


def test_internetdb_normalizes_into_the_typed_result(api_fixture):
    result = normalize_internetdb(api_fixture("internetdb.json"))
    assert result.ip == "203.0.113.44"
    assert result.ports == [22, 80, 443, 7547]
    assert result.tags == ["cdn", "iot"]
    assert result.vulns == ["CVE-2024-1234"]


def test_internetdb_404_shape_becomes_an_empty_result():
    result = normalize_internetdb({"detail": "No information available"})
    assert result.ip is None
    assert result.ports == []


def test_captcha_risk_is_low_for_a_clean_residential_address():
    risk, rationale = captcha_risk([], [], "residential", None)
    assert risk == "low"
    assert rationale


def test_captcha_risk_is_medium_for_a_hosting_address_with_no_listings():
    risk, rationale = captcha_risk([], [], "hosting", None)
    assert risk == "medium"
    assert "hosting" in rationale.lower()


def test_captcha_risk_is_high_when_a_blocklist_matches():
    risk, rationale = captcha_risk(["firehol_level1"], [], "residential", None)
    assert risk == "high"
    assert "firehol_level1" in rationale


def test_captcha_risk_is_high_on_a_real_dnsbl_listing():
    hits, _ = summarize_dnsbl([decode_dnsbl("zen.spamhaus.org", ["127.0.0.2"])])
    risk, rationale = captcha_risk([], hits, "residential", None)
    assert risk == "high"
    assert "zen.spamhaus.org" in rationale


def test_captcha_risk_escalates_on_a_high_abuseipdb_score():
    assert captcha_risk([], [], "residential", 90)[0] == "high"
    assert captcha_risk([], [], "residential", 30)[0] == "medium"
    assert captcha_risk([], [], "residential", 5)[0] == "low"


def test_build_reputation_marks_the_query_as_blocked_without_inventing_hits(api_fixture):
    rep = build_reputation(
        internetdb=normalize_internetdb(api_fixture("internetdb.json")),
        firehol_hits=[],
        dnsbl_outcomes=[decode_dnsbl("zen.spamhaus.org", ["127.255.255.254"])],
        ip_type="residential",
        abuseipdb_score=None,
        abuseipdb_reports=None,
    )
    assert rep.dnsbl_hits == []
    assert rep.dnsbl_query_blocked is True
    assert rep.captcha_risk == "low"


def test_build_reputation_without_dnsbl_leaves_the_field_none(api_fixture):
    rep = build_reputation(
        internetdb=normalize_internetdb(api_fixture("internetdb.json")),
        firehol_hits=["firehol_level1"],
        dnsbl_outcomes=None,
        ip_type="residential",
        abuseipdb_score=None,
        abuseipdb_reports=None,
    )
    assert rep.dnsbl_hits is None
    assert rep.dnsbl_query_blocked is False
    assert rep.captcha_risk == "high"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_reputation.py -q -k "internetdb or captcha or build_reputation"`
Expected: FAIL — `ImportError: cannot import name 'normalize_internetdb'`.

- [ ] **Step 4: Append to `src/netcheck/reputation.py`**

```python
from netcheck.models import InternetDbResult, Reputation


def normalize_internetdb(payload: dict) -> InternetDbResult:
    if "ip" not in payload:
        return InternetDbResult()
    return InternetDbResult(
        ip=payload.get("ip"),
        ports=list(payload.get("ports") or []),
        hostnames=list(payload.get("hostnames") or []),
        tags=list(payload.get("tags") or []),
        cpes=list(payload.get("cpes") or []),
        vulns=list(payload.get("vulns") or []),
    )


def captcha_risk(
    firehol_hits: list[str],
    dnsbl_hits: list[DnsblHit],
    ip_type: str,
    abuseipdb_score: int | None,
) -> tuple[str, str]:
    reasons: list[str] = []
    risk = "low"
    if firehol_hits:
        risk = "high"
        reasons.append(f"listed on {', '.join(firehol_hits)}")
    if dnsbl_hits:
        risk = "high"
        reasons.append(f"listed on {', '.join(h.zone for h in dnsbl_hits)}")
    if abuseipdb_score is not None and abuseipdb_score >= 50:
        risk = "high"
        reasons.append(f"AbuseIPDB confidence {abuseipdb_score}")
    elif abuseipdb_score is not None and abuseipdb_score >= 25 and risk == "low":
        risk = "medium"
        reasons.append(f"AbuseIPDB confidence {abuseipdb_score}")
    if risk == "low" and ip_type == "hosting":
        risk = "medium"
        reasons.append("egress looks like hosting/proxy space, which many sites challenge by default")
    if not reasons:
        reasons.append("no blocklist match and the address looks like ordinary end-user space")
    return risk, "; ".join(reasons)


def build_reputation(
    internetdb: InternetDbResult | None,
    firehol_hits: list[str],
    dnsbl_outcomes: list[DnsblOutcome] | None,
    ip_type: str,
    abuseipdb_score: int | None,
    abuseipdb_reports: int | None,
) -> Reputation:
    hits: list[DnsblHit] | None = None
    blocked = False
    if dnsbl_outcomes is not None:
        hits, blocked = summarize_dnsbl(dnsbl_outcomes)
    risk, rationale = captcha_risk(firehol_hits, hits or [], ip_type, abuseipdb_score)
    return Reputation(
        internetdb=internetdb,
        firehol_hits=firehol_hits,
        dnsbl_hits=hits,
        dnsbl_query_blocked=blocked,
        abuseipdb_score=abuseipdb_score,
        abuseipdb_reports=abuseipdb_reports,
        captcha_risk=risk,
        rationale=rationale,
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_reputation.py -q`
Expected: PASS, 19 tests.

- [ ] **Step 6: Append the query glue to `src/netcheck/reputation.py`**

```python
import asyncio

import dns.asyncresolver
import dns.exception


async def query_dnsbl(ip: str, zones: list[str], timeout: float) -> list[DnsblOutcome]:
    label = reverse_ip(ip)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    async def one(zone: str) -> DnsblOutcome:
        try:
            answer = await resolver.resolve(f"{label}.{zone}", "A")
        except dns.exception.DNSException:
            return DnsblOutcome(zone=zone, listed=False, codes=[])
        return decode_dnsbl(zone, sorted(record.address for record in answer))

    return list(await asyncio.gather(*(one(zone) for zone in zones)))


async def fetch_internetdb(client: httpx.AsyncClient, providers: Providers, ip: str) -> dict:
    response = await client.get(f"{providers.internetdb_url}{ip}")
    if response.status_code == 404:
        return {"detail": "No information available"}
    response.raise_for_status()
    return response.json()


async def fetch_abuseipdb(
    client: httpx.AsyncClient, providers: Providers, ip: str, key: str
) -> dict:
    response = await client.get(
        providers.abuseipdb_url,
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        headers={"Key": key, "Accept": "application/json"},
    )
    response.raise_for_status()
    return response.json()
```

A DNS failure for a zone yields an outcome with no answers and no error reason — "the zone did not answer" is not "the IP is clean" *and* is not "the IP is listed", and `summarize_dnsbl` treats it as neither.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/reputation.py tests/test_reputation.py tests/fixtures/api/internetdb.json
git commit -m "reputation: internetdb, captcha risk and reputation assembly"
```

---
## Phase 4 — Probes

### Task 25: `probes/latency.py` — ping summarization and backend fan-out

**Files:**
- Create: `src/netcheck/probes/latency.py`
- Test: `tests/test_prober_stats.py`

**Interfaces:**
- Consumes: `rtt_stats` (Task 9), `PingResult` (Task 4), `Capabilities` (Task 4), `choose_latency_backend` (Task 7).
- Produces:
  - `summarize_ping(label: str, host: str, resolved_ip: str | None, method: str, samples: list[float | None]) -> PingResult`
  - `async tcp_connect_rtt(host: str, port: int = 443, timeout: float = 2.0) -> float | None` — glue
  - `async ping_host(host: str, label: str, count: int, interval: float, timeout: float, backend: str) -> PingResult` — glue
  - `async ping_fanout(hosts: list[tuple[str, str]], caps: Capabilities, count: int, interval: float, timeout: float) -> list[PingResult]` — glue

**Testing note:** the ICMP, TCP and `cfL4` backends themselves are glue (real sockets, real network). What is tested here is the pure conversion of raw samples into a `PingResult` — including that the `method` tag survives, which the report depends on to avoid conflating TCP connection failures with ICMP packet loss (spec §9).

- [ ] **Step 1: Write the failing test**

`tests/test_prober_stats.py`:

```python
from __future__ import annotations

import pytest

from netcheck.probes.latency import summarize_ping


def test_summarize_builds_a_complete_ping_result():
    result = summarize_ping(
        label="cloudflare-dns",
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_dgram",
        samples=[10.0, 12.0, 14.0, 16.0],
    )
    assert result.label == "cloudflare-dns"
    assert result.host == "1.1.1.1"
    assert result.resolved_ip == "1.1.1.1"
    assert result.method == "icmp_dgram"
    assert result.sent == 4
    assert result.received == 4
    assert result.loss_pct == 0.0
    assert result.min_ms == 10.0
    assert result.avg_ms == 13.0
    assert result.max_ms == 16.0
    assert result.mdev_ms == pytest.approx(2.0)
    assert result.jitter_ms == pytest.approx(2.0)
    assert result.samples == [10.0, 12.0, 14.0, 16.0]


def test_summarize_keeps_timeout_positions_in_the_sample_list():
    result = summarize_ping("h", "example.test", None, "tcp", [None, 20.0, None, 24.0])
    assert result.samples == [None, 20.0, None, 24.0]
    assert result.sent == 4
    assert result.received == 2
    assert result.loss_pct == 50.0


def test_summarize_of_an_all_timeout_run_is_not_an_error():
    result = summarize_ping("h", "example.test", None, "icmp_win", [None, None, None])
    assert result.received == 0
    assert result.loss_pct == 100.0
    assert result.avg_ms is None
    assert result.jitter_ms is None


def test_summarize_of_a_single_sample_reports_zero_jitter():
    result = summarize_ping("h", "1.1.1.1", "1.1.1.1", "cfL4", [9.0])
    assert result.min_ms == result.avg_ms == result.max_ms == 9.0
    assert result.jitter_ms == 0.0
    assert result.mdev_ms == 0.0


def test_summarize_of_zero_probes_is_a_well_formed_empty_result():
    result = summarize_ping("h", "1.1.1.1", None, "none", [])
    assert result.sent == 0
    assert result.received == 0
    assert result.loss_pct == 0.0
    assert result.samples == []


def test_the_method_tag_is_preserved_verbatim():
    for method in ("icmp_win", "icmp_dgram", "icmp_raw", "tcp", "cfL4"):
        assert summarize_ping("h", "x", None, method, [1.0]).method == method
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_prober_stats.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.probes.latency'`.

- [ ] **Step 3: Implement the pure part of `src/netcheck/probes/latency.py`**

```python
from __future__ import annotations

import asyncio
import socket
import time

from netcheck.models import Capabilities, PingResult
from netcheck.netinfo import choose_latency_backend
from netcheck.stats import rtt_stats


def summarize_ping(
    label: str,
    host: str,
    resolved_ip: str | None,
    method: str,
    samples: list[float | None],
) -> PingResult:
    s = rtt_stats(samples)
    return PingResult(
        label=label,
        host=host,
        resolved_ip=resolved_ip,
        method=method,
        sent=s.sent,
        received=s.received,
        loss_pct=s.loss_pct,
        min_ms=s.min_ms,
        avg_ms=s.avg_ms,
        max_ms=s.max_ms,
        mdev_ms=s.mdev_ms,
        jitter_ms=s.jitter_ms,
        samples=samples,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_prober_stats.py -q`
Expected: PASS, 6 tests.

- [ ] **Step 5: Append the backend glue to `src/netcheck/probes/latency.py`**

```python
async def tcp_connect_rtt(host: str, port: int = 443, timeout: float = 2.0) -> float | None:
    began = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return (time.perf_counter() - began) * 1000.0


def _resolve(host: str) -> str | None:
    try:
        return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
    except (OSError, IndexError):
        return None


async def _icmp_samples(host: str, count: int, interval: float, timeout: float, backend: str) -> list[float | None]:
    if backend == "icmp_win":
        from netcheck.probes.icmp_win import ping_samples_win

        return await asyncio.to_thread(ping_samples_win, host, count, interval, timeout)
    from icmplib import async_ping

    privileged = backend == "icmp_raw"
    host_result = await async_ping(
        host, count=count, interval=interval, timeout=timeout, privileged=privileged
    )
    samples: list[float | None] = list(host_result.rtts)
    samples.extend([None] * (count - len(samples)))
    return samples


async def ping_host(
    host: str,
    label: str,
    count: int,
    interval: float,
    timeout: float,
    backend: str,
) -> PingResult:
    resolved = _resolve(host)
    if backend in ("icmp_win", "icmp_dgram", "icmp_raw"):
        try:
            samples = await _icmp_samples(host, count, interval, timeout, backend)
            return summarize_ping(label, host, resolved, backend, samples)
        except Exception:
            backend = "tcp"
    samples = []
    for index in range(count):
        if index:
            await asyncio.sleep(interval)
        samples.append(await tcp_connect_rtt(host, timeout=timeout))
    return summarize_ping(label, host, resolved, "tcp", samples)


async def ping_fanout(
    hosts: list[tuple[str, str]],
    caps: Capabilities,
    count: int,
    interval: float,
    timeout: float,
) -> list[PingResult]:
    backend = choose_latency_backend(caps)
    return list(
        await asyncio.gather(
            *(ping_host(host, label, count, interval, timeout, backend) for label, host in hosts)
        )
    )
```

An ICMP backend that throws at runtime silently degrades that host to TCP timing, and the `method` field records which one actually ran — the report never presents TCP connection failures as ICMP packet loss.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/probes/latency.py tests/test_prober_stats.py
git commit -m "latency: ping summarization and unprivileged backend fan-out"
```

---

### Task 26: `probes/icmp_win.py` — reply buffer parsing

**Files:**
- Create: `src/netcheck/probes/icmp_win.py`
- Test: `tests/test_icmp_win_parse.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `IcmpReply` NamedTuple: `address: str | None, status: int, rtt_ms: float | None, ttl: int`
  - `IP_SUCCESS`, `IP_TTL_EXPIRED_TRANSIT`, `IP_REQ_TIMED_OUT`, `IP_DEST_HOST_UNREACHABLE`, `IP_DEST_NET_UNREACHABLE` constants
  - `classify_status(status: int) -> str` — one of `ok | ttl_expired | timeout | unreachable | error`
  - `parse_echo_reply(buffer: bytes, pointer_size: int = 8) -> IcmpReply`

**Testing note:** driving the real Win32 API cannot be unit tested — it needs a Windows host and a live network, and mocking the whole of `Iphlpapi.dll` would test the mock, not the code. What *is* isolated and tested here is the byte-level decode of the `ICMP_ECHO_REPLY` structure the API writes into the caller's buffer, exercised with synthetic buffers for both pointer widths. That is where the real bugs live (field offsets, byte order, status codes).

- [ ] **Step 1: Write the failing test**

`tests/test_icmp_win_parse.py`:

```python
from __future__ import annotations

import struct

import pytest

from netcheck.probes.icmp_win import (
    IP_DEST_HOST_UNREACHABLE,
    IP_REQ_TIMED_OUT,
    IP_SUCCESS,
    IP_TTL_EXPIRED_TRANSIT,
    classify_status,
    parse_echo_reply,
)


def make_reply(address: str, status: int, rtt: int, ttl: int, pointer_size: int = 8) -> bytes:
    # ICMP_ECHO_REPLY: IPAddr(4) Status(4) RoundTripTime(4) DataSize(2) Reserved(2)
    # then a pointer (Data), then IP_OPTION_INFORMATION { Ttl Tos Flags OptionsSize }
    # followed by another pointer. Both pointers are alignment-padded to their width.
    packed = struct.pack("<4B", *(int(o) for o in address.split(".")))
    head = packed + struct.pack("<IIHH", status, rtt, 32, 0)
    head += b"\x00" * (pointer_size - (len(head) % pointer_size) if len(head) % pointer_size else 0)
    head += b"\x00" * pointer_size
    head += struct.pack("<4B", ttl, 0, 0, 0)
    head += b"\x00" * (pointer_size - 4 if pointer_size > 4 else 0)
    head += b"\x00" * pointer_size
    return head


def test_parses_a_successful_reply_on_64_bit():
    reply = parse_echo_reply(make_reply("1.1.1.1", IP_SUCCESS, 12, 57), pointer_size=8)
    assert reply.address == "1.1.1.1"
    assert reply.status == IP_SUCCESS
    assert reply.rtt_ms == 12.0
    assert reply.ttl == 57


def test_parses_a_successful_reply_on_32_bit():
    reply = parse_echo_reply(make_reply("8.8.4.4", IP_SUCCESS, 9, 120, pointer_size=4), pointer_size=4)
    assert reply.address == "8.8.4.4"
    assert reply.rtt_ms == 9.0
    assert reply.ttl == 120


def test_address_bytes_are_read_in_network_order():
    reply = parse_echo_reply(make_reply("192.168.1.34", IP_SUCCESS, 1, 64))
    assert reply.address == "192.168.1.34"


def test_a_ttl_expired_reply_keeps_the_intermediate_router_address():
    reply = parse_echo_reply(make_reply("10.64.0.1", IP_TTL_EXPIRED_TRANSIT, 8, 253))
    assert reply.address == "10.64.0.1"
    assert reply.status == IP_TTL_EXPIRED_TRANSIT
    assert reply.rtt_ms == 8.0


def test_a_timed_out_reply_has_no_address_and_no_rtt():
    reply = parse_echo_reply(make_reply("0.0.0.0", IP_REQ_TIMED_OUT, 0, 0))
    assert reply.address is None
    assert reply.rtt_ms is None
    assert reply.status == IP_REQ_TIMED_OUT


def test_a_truncated_buffer_is_reported_as_an_error_not_an_exception():
    reply = parse_echo_reply(b"\x01\x02")
    assert reply.address is None
    assert reply.rtt_ms is None
    assert reply.status == -1


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (IP_SUCCESS, "ok"),
        (IP_TTL_EXPIRED_TRANSIT, "ttl_expired"),
        (IP_REQ_TIMED_OUT, "timeout"),
        (IP_DEST_HOST_UNREACHABLE, "unreachable"),
        (-1, "error"),
        (11050, "error"),
    ],
)
def test_status_classification(status, expected):
    assert classify_status(status) == expected
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_icmp_win_parse.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.probes.icmp_win'`.

- [ ] **Step 3: Implement the parsing half of `src/netcheck/probes/icmp_win.py`**

```python
from __future__ import annotations

import struct
from typing import NamedTuple

IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013

_UNREACHABLE = {IP_DEST_NET_UNREACHABLE, IP_DEST_HOST_UNREACHABLE, 11001, 11004}
_HEAD = struct.Struct("<4BIIHH")


class IcmpReply(NamedTuple):
    address: str | None
    status: int
    rtt_ms: float | None
    ttl: int


def classify_status(status: int) -> str:
    if status == IP_SUCCESS:
        return "ok"
    if status == IP_TTL_EXPIRED_TRANSIT:
        return "ttl_expired"
    if status == IP_REQ_TIMED_OUT:
        return "timeout"
    if status in _UNREACHABLE:
        return "unreachable"
    return "error"


def parse_echo_reply(buffer: bytes, pointer_size: int = 8) -> IcmpReply:
    # Layout after the fixed head: the Data pointer is aligned to its own width,
    # then IP_OPTION_INFORMATION starts with Ttl as its first byte.
    head_size = _HEAD.size
    padding = (-head_size) % pointer_size
    ttl_offset = head_size + padding + pointer_size
    if len(buffer) < ttl_offset + 1:
        return IcmpReply(address=None, status=-1, rtt_ms=None, ttl=0)
    a, b, c, d, status, rtt, _data_size, _reserved = _HEAD.unpack_from(buffer, 0)
    ttl = buffer[ttl_offset]
    if status in (IP_REQ_TIMED_OUT,) or (a, b, c, d) == (0, 0, 0, 0):
        return IcmpReply(address=None, status=status, rtt_ms=None, ttl=ttl)
    return IcmpReply(address=f"{a}.{b}.{c}.{d}", status=status, rtt_ms=float(rtt), ttl=ttl)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_icmp_win_parse.py -q`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/probes/icmp_win.py tests/test_icmp_win_parse.py
git commit -m "icmp_win: decode ICMP_ECHO_REPLY buffers for both pointer widths"
```

---

### Task 27: `probes/icmp_win.py` — the `IcmpSendEcho2` engine

**Files:**
- Modify: `src/netcheck/probes/icmp_win.py` (append)

**Interfaces:**
- Consumes: Task 26's `parse_echo_reply`, `classify_status`.
- Produces:
  - `win_icmp_available() -> bool`
  - `echo_once(dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netcheck") -> IcmpReply`
  - `ping_samples_win(host: str, count: int, interval: float, timeout: float) -> list[float | None]` — called via `asyncio.to_thread` by Task 25
  - `trace_hops_win(dest: str, max_hops: int, timeout_ms: int) -> list[tuple[int, IcmpReply]]` — called by Task 28

**Testing note:** this task adds no tests. Every line of it is a `ctypes` call into `Iphlpapi.dll` on a live network — the testing policy names `ctypes` calls as glue, and the only meaningful verification is running it on a Windows host, which Step 3 does explicitly. The decode logic it depends on is already covered by Task 26.

- [ ] **Step 1: Append the engine to `src/netcheck/probes/icmp_win.py`**

```python
import ctypes
import platform
import socket
import time
from ctypes import wintypes

_REPLY_BUFFER_SIZE = 4096


class _IpOptionInformation(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


def win_icmp_available() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        ctypes.WinDLL("Iphlpapi.dll")
    except OSError:
        return False
    return True


def _handle():
    iphlpapi = ctypes.WinDLL("Iphlpapi.dll")
    iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
    handle = iphlpapi.IcmpCreateFile()
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("IcmpCreateFile failed")
    return iphlpapi, handle


def echo_once(dest: str, ttl: int, timeout_ms: int, payload: bytes = b"netcheck") -> IcmpReply:
    iphlpapi, handle = _handle()
    try:
        options = _IpOptionInformation(Ttl=ttl, Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
        buffer = ctypes.create_string_buffer(_REPLY_BUFFER_SIZE)
        address = struct.unpack("<I", socket.inet_aton(dest))[0]
        count = iphlpapi.IcmpSendEcho2(
            handle,
            None,
            None,
            None,
            ctypes.c_uint32(address),
            payload,
            ctypes.c_ushort(len(payload)),
            ctypes.byref(options),
            buffer,
            ctypes.c_uint32(_REPLY_BUFFER_SIZE),
            ctypes.c_uint32(timeout_ms),
        )
        if count == 0:
            return IcmpReply(address=None, status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)
        return parse_echo_reply(buffer.raw, pointer_size=ctypes.sizeof(ctypes.c_void_p))
    finally:
        iphlpapi.IcmpCloseHandle(handle)


def ping_samples_win(host: str, count: int, interval: float, timeout: float) -> list[float | None]:
    dest = socket.gethostbyname(host)
    timeout_ms = int(timeout * 1000)
    samples: list[float | None] = []
    for index in range(count):
        if index:
            time.sleep(interval)
        reply = echo_once(dest, ttl=128, timeout_ms=timeout_ms)
        samples.append(reply.rtt_ms if classify_status(reply.status) == "ok" else None)
    return samples


def trace_hops_win(dest: str, max_hops: int, timeout_ms: int) -> list[tuple[int, IcmpReply]]:
    address = socket.gethostbyname(dest)
    hops: list[tuple[int, IcmpReply]] = []
    for ttl in range(1, max_hops + 1):
        reply = echo_once(address, ttl=ttl, timeout_ms=timeout_ms)
        hops.append((ttl, reply))
        if classify_status(reply.status) == "ok":
            break
    return hops
```

`IcmpSendEcho2` is the same unprivileged API `tracert.exe` uses internally: no Administrator, no Npcap, stdlib only (spec §9).

- [ ] **Step 2: Verify on a Windows host**

Run (Windows only — skip and note it in the commit message if the dev machine is not Windows):

```bash
uv run python -c "from netcheck.probes.icmp_win import ping_samples_win, trace_hops_win, classify_status; print(ping_samples_win('1.1.1.1', 3, 0.2, 2.0)); print([(t, r.address, classify_status(r.status)) for t, r in trace_hops_win('1.1.1.1', 8, 1500)])"
```

Expected: three float RTTs (or `None` for a dropped probe), then a list of hops whose last entry has status class `ok` and address `1.1.1.1`. No traceback, and **no elevation prompt**.

- [ ] **Step 3: Commit**

```bash
git add src/netcheck/probes/icmp_win.py
git commit -m "icmp_win: unprivileged IcmpSendEcho2 ping and traceroute engine"
```

---

### Task 28: `probes/traceroute.py` — the cascade

**Files:**
- Create: `src/netcheck/probes/traceroute.py`
- Test: `tests/test_traceroute_cascade.py`

**Interfaces:**
- Consumes: `Capabilities`, `TraceResult`, `TraceHop` (Task 4); `build_trace_result` (Task 13); `trace_hops_win`, `classify_status` (Task 27).
- Produces:
  - `tier_order(caps: Capabilities) -> list[str]`
  - `async run_cascade(tiers: list[tuple[str, Callable[[], Awaitable[TraceResult]]]]) -> TraceResult`
  - `hops_from_win_replies(replies: list[tuple[int, IcmpReply]]) -> list[TraceHop]`
  - `async traceroute(target: str, caps: Capabilities, max_hops: int, cycles: int, timeout: float, semaphore: asyncio.Semaphore | None = None) -> TraceResult` — glue

- [ ] **Step 1: Write the failing test**

`tests/test_traceroute_cascade.py`:

```python
from __future__ import annotations

import asyncio

import pytest

from netcheck.models import Capabilities, TraceHop, TraceResult
from netcheck.probes.icmp_win import IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, IcmpReply
from netcheck.probes.traceroute import hops_from_win_replies, run_cascade, tier_order


def caps(**kw) -> Capabilities:
    base = dict(os_name="Linux", icmp_dgram=False, icmp_raw=False, icmp_win_api=False)
    base.update(kw)
    return Capabilities(**base)


def test_tier_order_puts_mtr_first_when_available():
    order = tier_order(caps(mtr_binary="/usr/bin/mtr", icmp_dgram=True, traceroute_binary="/usr/bin/traceroute"))
    assert order == ["mtr_json", "icmplib", "system_traceroute"]


def test_tier_order_on_windows_uses_the_win_api_before_the_binary():
    order = tier_order(caps(os_name="Windows", icmp_win_api=True, traceroute_binary="C:\\tracert.exe"))
    assert order == ["icmp_win", "system_traceroute"]


def test_tier_order_on_windows_still_prefers_mtr_if_someone_installed_it():
    order = tier_order(caps(os_name="Windows", mtr_binary="C:\\mtr.exe", icmp_win_api=True))
    assert order[0] == "mtr_json"
    assert order[1] == "icmp_win"


def test_tier_order_without_any_icmp_falls_back_to_the_system_binary():
    assert tier_order(caps(traceroute_binary="/usr/bin/traceroute")) == ["system_traceroute"]


def test_tier_order_with_nothing_available_is_empty():
    assert tier_order(caps()) == []


def good(name: str) -> TraceResult:
    return TraceResult(target="1.1.1.1", backend=name, hops=[TraceHop(ttl=1, ip="192.168.1.1")], completed=True)


async def test_cascade_uses_the_first_tier_that_works():
    calls: list[str] = []

    async def tier1() -> TraceResult:
        calls.append("t1")
        return good("mtr_json")

    async def tier2() -> TraceResult:
        calls.append("t2")
        return good("icmplib")

    result = await run_cascade([("mtr_json", tier1), ("icmplib", tier2)])
    assert result.backend == "mtr_json"
    assert calls == ["t1"]


async def test_cascade_falls_through_when_a_tier_raises():
    calls: list[str] = []

    async def tier1() -> TraceResult:
        calls.append("t1")
        raise FileNotFoundError("mtr not on PATH")

    async def tier2() -> TraceResult:
        calls.append("t2")
        return good("icmplib")

    result = await run_cascade([("mtr_json", tier1), ("icmplib", tier2)])
    assert result.backend == "icmplib"
    assert calls == ["t1", "t2"]


async def test_cascade_falls_through_when_a_tier_returns_no_hops():
    async def tier1() -> TraceResult:
        return TraceResult(target="1.1.1.1", backend="mtr_json", hops=[])

    async def tier2() -> TraceResult:
        return good("system_traceroute")

    result = await run_cascade([("mtr_json", tier1), ("system_traceroute", tier2)])
    assert result.backend == "system_traceroute"


async def test_cascade_tries_every_tier_in_order():
    calls: list[str] = []

    def failing(name: str):
        async def tier() -> TraceResult:
            calls.append(name)
            raise OSError(name)

        return tier

    async def last() -> TraceResult:
        calls.append("system")
        return good("system_traceroute")

    result = await run_cascade(
        [("mtr_json", failing("mtr")), ("icmp_win", failing("win")), ("icmplib", failing("lib")), ("system_traceroute", last)]
    )
    assert calls == ["mtr", "win", "lib", "system"]
    assert result.backend == "system_traceroute"


async def test_cascade_exhaustion_yields_a_none_backend_not_an_exception():
    async def boom() -> TraceResult:
        raise OSError("nope")

    result = await run_cascade([("mtr_json", boom), ("icmplib", boom)])
    assert isinstance(result, TraceResult)
    assert result.backend == "none"
    assert result.hops == []
    assert result.completed is False


async def test_cascade_with_no_tiers_at_all_yields_a_none_backend():
    result = await run_cascade([])
    assert result.backend == "none"


async def test_cascade_never_swallows_cancellation():
    async def cancelled() -> TraceResult:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_cascade([("mtr_json", cancelled)])


def test_win_replies_become_hops_with_ttl_expiry_handled():
    replies = [
        (1, IcmpReply(address="192.168.1.1", status=IP_TTL_EXPIRED_TRANSIT, rtt_ms=1.0, ttl=64)),
        (2, IcmpReply(address=None, status=IP_REQ_TIMED_OUT, rtt_ms=None, ttl=0)),
        (3, IcmpReply(address="1.1.1.1", status=IP_SUCCESS, rtt_ms=12.0, ttl=57)),
    ]
    hops = hops_from_win_replies(replies)
    assert [h.ttl for h in hops] == [1, 2, 3]
    assert hops[0].ip == "192.168.1.1"
    assert hops[0].probes == [1.0]
    assert hops[1].ip is None
    assert hops[1].probes == [None]
    assert hops[1].loss_pct == 100.0
    assert hops[2].ip == "1.1.1.1"
    assert hops[2].avg_ms == 12.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_traceroute_cascade.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.probes.traceroute'`.

- [ ] **Step 3: Implement the pure cascade logic in `src/netcheck/probes/traceroute.py`**

```python
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from netcheck.models import Capabilities, TraceHop, TraceResult
from netcheck.probes.icmp_win import IcmpReply, classify_status
from netcheck.traceparse import finalize_hop


def tier_order(caps: Capabilities) -> list[str]:
    order: list[str] = []
    if caps.mtr_binary:
        order.append("mtr_json")
    if caps.icmp_win_api:
        order.append("icmp_win")
    elif caps.icmp_dgram or caps.icmp_raw:
        order.append("icmplib")
    if caps.traceroute_binary:
        order.append("system_traceroute")
    return order


async def run_cascade(tiers: list[tuple[str, Callable[[], Awaitable[TraceResult]]]]) -> TraceResult:
    for _name, tier in tiers:
        try:
            result = await tier()
        except asyncio.CancelledError:
            raise
        except BaseException:  # noqa: BLE001 - a dead tier is data, the next tier gets its turn
            continue
        if result.hops:
            return result
    return TraceResult(backend="none", hops=[], completed=False)


def hops_from_win_replies(replies: list[tuple[int, IcmpReply]]) -> list[TraceHop]:
    hops: list[TraceHop] = []
    for ttl, reply in replies:
        kind = classify_status(reply.status)
        rtt = reply.rtt_ms if kind in ("ok", "ttl_expired") else None
        hops.append(finalize_hop(TraceHop(ttl=ttl, ip=reply.address, probes=[rtt])))
    return hops
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_traceroute_cascade.py -q`
Expected: PASS, 13 tests.

- [ ] **Step 5: Append the tier implementations (glue) to `src/netcheck/probes/traceroute.py`**

```python
import json
import platform
import shutil

from netcheck.traceparse import build_trace_result


async def _run(args: list[str], timeout: float) -> str:
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise
    return stdout.decode(_console_encoding(), errors="replace")


def _console_encoding() -> str:
    # Windows console tools emit the OEM code page (cp866 on Russian Windows),
    # which is why every parser here works on decoded text and never on bytes.
    if platform.system() != "Windows":
        return "utf-8"
    import ctypes

    try:
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        return "utf-8"


async def _tier_mtr(target: str, binary: str, cycles: int, max_hops: int, timeout: float) -> TraceResult:
    text = await _run(
        [binary, "--json", "--report-cycles", str(cycles), "--max-ttl", str(max_hops), target], timeout
    )
    payload = json.loads(text)
    report = payload.get("report") or {}
    hops = []
    for entry in report.get("hubs") or []:
        hop = TraceHop(
            ttl=entry.get("count", 0),
            ip=None if entry.get("host") in ("???", None) else entry.get("host"),
            probes=[],
            loss_pct=float(entry.get("Loss%", 0.0)),
            min_ms=entry.get("Best"),
            avg_ms=entry.get("Avg"),
            max_ms=entry.get("Wrst"),
            jitter_ms=entry.get("StDev"),
        )
        hops.append(hop)
    return TraceResult(
        target=target,
        backend="mtr_json",
        hops=hops,
        cycles=cycles,
        completed=bool(hops) and hops[-1].ip is not None,
    )


async def _tier_icmp_win(target: str, max_hops: int, timeout: float) -> TraceResult:
    from netcheck.probes.icmp_win import trace_hops_win

    replies = await asyncio.to_thread(trace_hops_win, target, max_hops, int(timeout * 1000))
    hops = hops_from_win_replies(replies)
    return TraceResult(
        target=target,
        backend="icmp_win",
        hops=hops,
        cycles=1,
        completed=bool(hops) and classify_status(replies[-1][1].status) == "ok",
        max_hops_reached=bool(hops) and hops[-1].ttl >= max_hops,
    )


async def _tier_icmplib(target: str, max_hops: int, timeout: float, privileged: bool) -> TraceResult:
    from icmplib import async_traceroute

    raw = await async_traceroute(target, max_hops=max_hops, timeout=timeout, privileged=privileged)
    hops = [
        finalize_hop(TraceHop(ttl=h.distance, ip=h.address, probes=list(h.rtts)))
        for h in raw
    ]
    return TraceResult(
        target=target,
        backend="icmplib",
        hops=hops,
        cycles=1,
        completed=bool(hops) and hops[-1].ip is not None,
        max_hops_reached=bool(hops) and hops[-1].ttl >= max_hops,
    )


async def _tier_system(target: str, binary: str, max_hops: int, timeout: float) -> TraceResult:
    os_name = platform.system()
    args = (
        [binary, "-h", str(max_hops), "-w", "2", target]
        if os_name == "Windows"
        else [binary, "-m", str(max_hops), "-w", "2", target]
    )
    text = await _run(args, timeout)
    return build_trace_result(text, os_name, target=target, resolved_ip=None, max_hops=max_hops)


async def traceroute(
    target: str,
    caps: Capabilities,
    max_hops: int,
    cycles: int,
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
) -> TraceResult:
    builders = {
        "mtr_json": lambda: _tier_mtr(target, caps.mtr_binary or shutil.which("mtr") or "mtr", cycles, max_hops, timeout),
        "icmp_win": lambda: _tier_icmp_win(target, max_hops, timeout),
        "icmplib": lambda: _tier_icmplib(target, max_hops, timeout, privileged=not caps.icmp_dgram),
        "system_traceroute": lambda: _tier_system(target, caps.traceroute_binary or "traceroute", max_hops, timeout),
    }
    tiers = [(name, builders[name]) for name in tier_order(caps)]
    if semaphore is None:
        return await run_cascade(tiers)
    async with semaphore:
        return await run_cascade(tiers)
```

The semaphore is not optional decoration: parallel traceroutes to different targets share early hops and inflate each other's latency, so `cli.py` passes a semaphore of `probing.trace_concurrency` (spec §12).

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/probes/traceroute.py tests/test_traceroute_cascade.py
git commit -m "traceroute: mtr to icmp_win to icmplib to system-binary cascade"
```

---

### Task 29: `probes/dns_leak.py` — leak detection logic

**Files:**
- Create: `src/netcheck/probes/dns_leak.py`
- Test: `tests/test_dns_leak.py`

**Interfaces:**
- Consumes: `AdapterLeakResult`, `DnsLeak` (Task 4).
- Produces:
  - `parse_akahelp(records: list[str]) -> dict[str, str]`
  - `parse_myaddr(records: list[str]) -> str | None`
  - `detect_ecs_leak(akahelp: dict[str, str]) -> bool`
  - `build_adapter_result(adapter: str, resolvers: list[str], echoed_ip: str | None, echoed_asn: str | None, egress_asn: str | None) -> AdapterLeakResult`
  - `build_dns_leak(results: list[AdapterLeakResult], ecs_leaked: bool) -> DnsLeak`

- [ ] **Step 1: Write the failing test**

`tests/test_dns_leak.py`:

```python
from __future__ import annotations

from netcheck.probes.dns_leak import (
    build_adapter_result,
    build_dns_leak,
    detect_ecs_leak,
    parse_akahelp,
    parse_myaddr,
)


def test_akahelp_txt_records_become_a_flat_mapping():
    records = ['"ns" "203.0.113.9"', '"ecs" "198.51.100.0/24"', '"cip" "203.0.113.44"']
    assert parse_akahelp(records) == {
        "ns": "203.0.113.9",
        "ecs": "198.51.100.0/24",
        "cip": "203.0.113.44",
    }


def test_akahelp_records_without_quotes_are_handled_too():
    assert parse_akahelp(["ns 203.0.113.9"]) == {"ns": "203.0.113.9"}


def test_akahelp_ignores_records_it_cannot_split():
    assert parse_akahelp(["garbage", '"ns" "1.2.3.4"']) == {"ns": "1.2.3.4"}


def test_myaddr_returns_the_echoed_resolver_address():
    assert parse_myaddr(['"203.0.113.9"']) == "203.0.113.9"
    assert parse_myaddr(["203.0.113.9"]) == "203.0.113.9"


def test_myaddr_of_no_answer_is_none():
    assert parse_myaddr([]) is None
    assert parse_myaddr(['"not an ip"']) is None


def test_ecs_leak_is_detected_when_a_client_subnet_is_echoed():
    assert detect_ecs_leak({"ecs": "198.51.100.0/24"}) is True


def test_no_ecs_leak_when_the_field_is_absent_or_a_wildcard():
    assert detect_ecs_leak({}) is False
    assert detect_ecs_leak({"ecs": ""}) is False
    assert detect_ecs_leak({"ecs": "0.0.0.0/0"}) is False


def test_adapter_result_flags_a_resolver_in_a_different_asn():
    result = build_adapter_result(
        adapter="Wi-Fi",
        resolvers=["192.168.1.1"],
        echoed_ip="203.0.113.9",
        echoed_asn="AS64501",
        egress_asn="AS64500",
    )
    assert result.matches_egress_asn is False
    assert result.adapter == "Wi-Fi"
    assert result.configured_resolvers == ["192.168.1.1"]


def test_adapter_result_is_clean_when_the_asns_agree():
    result = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    assert result.matches_egress_asn is True


def test_adapter_result_is_unknown_when_either_asn_is_missing():
    assert build_adapter_result("eth0", ["1.1.1.1"], "1.1.1.1", None, "AS64500").matches_egress_asn is None
    assert build_adapter_result("eth0", ["1.1.1.1"], "1.1.1.1", "AS13335", None).matches_egress_asn is None


def test_adapter_result_asn_comparison_is_case_insensitive():
    assert build_adapter_result("eth0", ["1.1.1.1"], "1.1.1.1", "as64500", "AS64500").matches_egress_asn is True


def test_dns_leak_note_names_the_leaking_adapter():
    leaking = build_adapter_result("Wi-Fi", ["192.168.1.1"], "203.0.113.9", "AS64501", "AS64500")
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean, leaking], ecs_leaked=False)
    assert leak.ecs_leaked is False
    assert "Wi-Fi" in leak.note
    assert "browser" in leak.note.lower()


def test_dns_leak_note_is_clean_when_every_adapter_agrees():
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean], ecs_leaked=False)
    assert "no adapter" in leak.note.lower()


def test_dns_leak_note_mentions_ecs_when_the_subnet_leaked():
    clean = build_adapter_result("wg0", ["10.7.0.1"], "203.0.113.44", "AS64500", "AS64500")
    leak = build_dns_leak([clean], ecs_leaked=True)
    assert leak.ecs_leaked is True
    assert "client subnet" in leak.note.lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_dns_leak.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.probes.dns_leak'`.

- [ ] **Step 3: Implement the pure logic in `src/netcheck/probes/dns_leak.py`**

```python
from __future__ import annotations

import ipaddress

from netcheck.models import AdapterLeakResult, DnsLeak

_LEAK_NOTE = (
    "This test only sees resolvers configured at the OS level. A browser using DoH "
    "or DoT bypasses them entirely and is not covered here."
)


def _unquote(text: str) -> str:
    return text.strip().strip('"')


def parse_akahelp(records: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for record in records:
        parts = [_unquote(part) for part in record.replace('" "', '"\t"').split("\t")]
        if len(parts) != 2:
            parts = [_unquote(p) for p in record.split(None, 1)]
        if len(parts) != 2 or not parts[0]:
            continue
        mapping[parts[0]] = parts[1]
    return mapping


def parse_myaddr(records: list[str]) -> str | None:
    for record in records:
        candidate = _unquote(record)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None


def detect_ecs_leak(akahelp: dict[str, str]) -> bool:
    ecs = akahelp.get("ecs", "").strip()
    if not ecs or ecs.startswith("0.0.0.0/0") or ecs.startswith("::/0"):
        return False
    return True


def build_adapter_result(
    adapter: str,
    resolvers: list[str],
    echoed_ip: str | None,
    echoed_asn: str | None,
    egress_asn: str | None,
) -> AdapterLeakResult:
    matches: bool | None = None
    if echoed_asn and egress_asn:
        matches = echoed_asn.upper() == egress_asn.upper()
    return AdapterLeakResult(
        adapter=adapter,
        configured_resolvers=list(resolvers),
        echoed_ip=echoed_ip,
        echoed_asn=echoed_asn,
        matches_egress_asn=matches,
    )


def build_dns_leak(results: list[AdapterLeakResult], ecs_leaked: bool) -> DnsLeak:
    leaking = [r.adapter for r in results if r.matches_egress_asn is False]
    parts: list[str] = []
    if leaking:
        parts.append(
            f"DNS queries from {', '.join(leaking)} resolve through a network outside the egress ASN."
        )
    else:
        parts.append("No adapter resolves DNS outside the egress ASN.")
    if ecs_leaked:
        parts.append("The resolver forwards your EDNS Client Subnet, exposing your network to authoritative servers.")
    parts.append(_LEAK_NOTE)
    return DnsLeak(per_adapter=results, ecs_leaked=ecs_leaked, note=" ".join(parts))
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_dns_leak.py -q`
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/probes/dns_leak.py tests/test_dns_leak.py
git commit -m "dns_leak: per-adapter asn mismatch and ecs leak detection"
```

---

### Task 30: `probes/dns_leak.py` — resolver enumeration and echo probes

**Files:**
- Modify: `src/netcheck/probes/dns_leak.py` (append)

**Interfaces:**
- Consumes: Task 29's helpers; `LocalNet` (Task 4); `parse_cymru_origin` (Task 20).
- Produces:
  - `async echo_probe(resolver_ip: str, timeout: float) -> tuple[str | None, dict[str, str]]`
  - `async asn_for_ip(ip: str, zone: str, timeout: float) -> str | None`
  - `async collect_dns_leak(local: LocalNet, egress_asn: str | None, cymru_zone: str, timeout: float) -> DnsLeak` — glue

**Testing note:** enumeration and the echo probes are live DNS against third-party servers — glue by the testing policy, and untestable without either network access or mocking dnspython so thoroughly that only the mock gets exercised. The detection logic they feed is fully covered by Task 29.

- [ ] **Step 1: Append to `src/netcheck/probes/dns_leak.py`**

```python
import asyncio

import dns.asyncresolver
import dns.exception

from netcheck.bgp import parse_cymru_origin
from netcheck.models import LocalNet

MYADDR_NAME = "o-o.myaddr.l.google.com"
AKAHELP_NAME = "whoami.ds.akahelp.net"


async def _txt(resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


def _resolver_for(server: str, timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.lifetime = timeout
    return resolver


async def echo_probe(resolver_ip: str, timeout: float) -> tuple[str | None, dict[str, str]]:
    resolver = _resolver_for(resolver_ip, timeout)
    myaddr, akahelp = await asyncio.gather(
        _txt(resolver, MYADDR_NAME), _txt(resolver, AKAHELP_NAME)
    )
    parsed = parse_akahelp(akahelp)
    return parse_myaddr(myaddr) or parsed.get("ns"), parsed


async def asn_for_ip(ip: str, zone: str, timeout: float) -> str | None:
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
    except AttributeError:
        return None
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    records = await _txt(resolver, f"{reversed_ip}.{zone}")
    for record in records:
        parsed = parse_cymru_origin(record)
        if parsed.get("asn"):
            return parsed["asn"]
    return None


async def collect_dns_leak(
    local: LocalNet,
    egress_asn: str | None,
    cymru_zone: str,
    timeout: float,
) -> DnsLeak:
    results: list[AdapterLeakResult] = []
    ecs_leaked = False
    for adapter, resolvers in local.dns_servers_per_adapter.items():
        if not resolvers:
            continue
        try:
            echoed_ip, akahelp = await echo_probe(resolvers[0], timeout)
        except dns.exception.DNSException:
            echoed_ip, akahelp = None, {}
        ecs_leaked = ecs_leaked or detect_ecs_leak(akahelp)
        echoed_asn = await asn_for_ip(echoed_ip, cymru_zone, timeout) if echoed_ip else None
        results.append(build_adapter_result(adapter, resolvers, echoed_ip, echoed_asn, egress_asn))
    return build_dns_leak(results, ecs_leaked)
```

Enumeration is deliberately per-adapter rather than "the system resolver": the case worth catching is a clean tunnel adapter alongside a Wi-Fi adapter still holding the ISP resolver (spec §6).

- [ ] **Step 2: Verify the probe runs against a public resolver**

Run: `uv run python -c "import asyncio; from netcheck.probes.dns_leak import echo_probe; print(asyncio.run(echo_probe('1.1.1.1', 4.0)))"`
Expected: a tuple whose first element is a public IPv4 address (one of Cloudflare's resolver egress addresses) and whose second element is a dict containing at least an `ns` key. No traceback.

- [ ] **Step 3: Commit**

```bash
git add src/netcheck/probes/dns_leak.py
git commit -m "dns_leak: per-adapter resolver enumeration and echo probes"
```

---

## Phase 5 — Speed

### Task 31: `speed.py` — throughput math and the `cfL4` header

**Files:**
- Create: `src/netcheck/speed.py`
- Test: `tests/test_speed_math.py`

**Interfaces:**
- Consumes: `CfL4Stats`, `TierAttempt`, `SpeedResult` (Task 4); `percentile` (Task 9).
- Produces:
  - `mbps(bytes_transferred: int, seconds: float) -> float`
  - `throughput_from_samples(samples: list[tuple[int, float]], p: float = 90.0) -> float`
  - `parse_server_timing_cfl4(header: str) -> CfL4Stats | None`
  - `bufferbloat_delta(idle_rtt_ms: float | None, loaded_rtts_ms: list[float]) -> float | None`

- [ ] **Step 1: Write the failing test**

`tests/test_speed_math.py`:

```python
from __future__ import annotations

import pytest

from netcheck.speed import bufferbloat_delta, mbps, parse_server_timing_cfl4, throughput_from_samples


def test_mbps_converts_bytes_and_seconds():
    assert mbps(1_000_000, 1.0) == pytest.approx(8.0)
    assert mbps(12_500_000, 1.0) == pytest.approx(100.0)
    assert mbps(25_000_000, 2.0) == pytest.approx(100.0)


def test_mbps_of_a_zero_or_negative_interval_is_zero_not_infinity():
    # Zero-duration timing math is exactly where inf leaks into the JSON report.
    assert mbps(1_000_000, 0.0) == 0.0
    assert mbps(1_000_000, -1.0) == 0.0


def test_mbps_of_no_bytes_is_zero():
    assert mbps(0, 1.5) == 0.0


def test_throughput_uses_the_ninetieth_percentile_of_the_samples():
    samples = [(1_000_000, 1.0), (1_000_000, 0.5), (1_000_000, 0.4), (1_000_000, 0.25)]
    # Per-sample Mbps: 8, 16, 20, 32 -> p90 interpolates to 28.4
    assert throughput_from_samples(samples) == pytest.approx(28.4)


def test_throughput_of_a_single_sample_is_that_sample():
    assert throughput_from_samples([(12_500_000, 1.0)]) == pytest.approx(100.0)


def test_throughput_of_no_samples_is_zero():
    assert throughput_from_samples([]) == 0.0


def test_cfl4_header_is_parsed_into_typed_stats():
    header = (
        'cfL4;desc="?proto=tcp&rtt=12345&min_rtt=11000&rtt_var=1500&sent=100&recv=200'
        '&lost=0&retrans=0&sent_bytes=1000&recv_bytes=1048576&delivery_rate=35000000'
        '&cwnd=42&unsent_bytes=0&cid=abcdef&ts=1&x=0"'
    )
    stats = parse_server_timing_cfl4(header)
    assert stats is not None
    assert stats.rtt_ms == pytest.approx(12.345)
    assert stats.min_rtt_ms == pytest.approx(11.0)
    assert stats.rtt_var_ms == pytest.approx(1.5)
    assert stats.delivery_rate_bps == 35000000
    assert stats.cwnd == 42
    assert stats.unsent_bytes == 0
    assert stats.recv_bytes == 1048576


def test_cfl4_parsing_picks_its_entry_out_of_a_multi_metric_header():
    header = 'cfRequestDuration;dur=42.1, cfL4;desc="?proto=tcp&rtt=9000&cwnd=10", cfCacheStatus;desc="HIT"'
    stats = parse_server_timing_cfl4(header)
    assert stats is not None
    assert stats.rtt_ms == pytest.approx(9.0)
    assert stats.cwnd == 10
    assert stats.delivery_rate_bps is None


def test_cfl4_parsing_of_a_header_without_the_entry_is_none():
    assert parse_server_timing_cfl4("cfCacheStatus;desc=HIT") is None
    assert parse_server_timing_cfl4("") is None


def test_cfl4_parsing_survives_unexpected_values():
    stats = parse_server_timing_cfl4('cfL4;desc="?proto=tcp&rtt=notanumber&cwnd=7"')
    assert stats is not None
    assert stats.rtt_ms is None
    assert stats.cwnd == 7


def test_bufferbloat_delta_is_the_rise_over_the_idle_baseline():
    assert bufferbloat_delta(12.0, [15.0, 60.0, 200.0, 210.0]) == pytest.approx(185.4)


def test_bufferbloat_delta_never_goes_negative():
    assert bufferbloat_delta(50.0, [10.0, 12.0, 11.0]) == 0.0


def test_bufferbloat_delta_needs_both_a_baseline_and_samples():
    assert bufferbloat_delta(None, [10.0]) is None
    assert bufferbloat_delta(12.0, []) is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_speed_math.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.speed'`.

- [ ] **Step 3: Implement the math in `src/netcheck/speed.py`**

```python
from __future__ import annotations

import re
from urllib.parse import parse_qs

from netcheck.models import CfL4Stats
from netcheck.stats import percentile

_CFL4_RE = re.compile(r'cfL4\s*;\s*desc\s*=\s*"?\??(?P<query>[^",]*)"?')


def mbps(bytes_transferred: int, seconds: float) -> float:
    if seconds <= 0 or bytes_transferred <= 0:
        return 0.0
    return (bytes_transferred * 8) / seconds / 1_000_000


def throughput_from_samples(samples: list[tuple[int, float]], p: float = 90.0) -> float:
    rates = [mbps(size, duration) for size, duration in samples]
    rates = [rate for rate in rates if rate > 0]
    if not rates:
        return 0.0
    return round(percentile(rates, p), 3)


def _as_int(value: str | None) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _us_to_ms(value: str | None) -> float | None:
    number = _as_int(value)
    return None if number is None else round(number / 1000.0, 3)


def parse_server_timing_cfl4(header: str) -> CfL4Stats | None:
    match = _CFL4_RE.search(header or "")
    if not match:
        return None
    fields = {k: v[0] for k, v in parse_qs(match.group("query"), keep_blank_values=True).items()}
    return CfL4Stats(
        rtt_ms=_us_to_ms(fields.get("rtt")),
        min_rtt_ms=_us_to_ms(fields.get("min_rtt")),
        rtt_var_ms=_us_to_ms(fields.get("rtt_var")),
        delivery_rate_bps=_as_int(fields.get("delivery_rate")),
        cwnd=_as_int(fields.get("cwnd")),
        unsent_bytes=_as_int(fields.get("unsent_bytes")),
        recv_bytes=_as_int(fields.get("recv_bytes")),
    )


def bufferbloat_delta(idle_rtt_ms: float | None, loaded_rtts_ms: list[float]) -> float | None:
    if idle_rtt_ms is None or not loaded_rtts_ms:
        return None
    loaded = percentile(sorted(loaded_rtts_ms), 95.0)
    return round(max(0.0, loaded - idle_rtt_ms), 3)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_speed_math.py -q`
Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/speed.py tests/test_speed_math.py
git commit -m "speed: throughput math, cfL4 header parsing, bufferbloat delta"
```

---

### Task 32: `speed.py` — the cascade

**Files:**
- Modify: `src/netcheck/speed.py` (append)
- Test: `tests/test_speed_math.py` (append)

**Interfaces:**
- Consumes: Task 31's math; `TierAttempt`, `SpeedResult` (Task 4); `Speedtest` config (Task 5).
- Produces:
  - `async run_speed_cascade(tiers: list[tuple[str, Callable[[], Awaitable[SpeedResult]]]]) -> SpeedResult`
  - `async tier_ookla(binary: str, server: str | None, timeout: float) -> SpeedResult` — glue
  - `async tier_cloudflare(client, cfg: Speedtest, timeout: float) -> SpeedResult` — glue
  - `async tier_fastcom(client, cfg: Speedtest, timeout: float) -> SpeedResult` — glue
  - `async tier_ndt7(client, cfg: Speedtest, timeout: float) -> SpeedResult` — glue, opt-in
  - `NDT7_CONSENT_NOTICE: str`

- [ ] **Step 1: Write the failing test (append to `tests/test_speed_math.py`)**

```python
from netcheck.models import SpeedResult, TierAttempt
from netcheck.speed import NDT7_CONSENT_NOTICE, run_speed_cascade


async def test_cascade_stops_at_the_first_tier_that_returns_a_download_figure():
    calls: list[str] = []

    async def ookla() -> SpeedResult:
        calls.append("ookla")
        return SpeedResult(method="ookla_bin", download_mbps=312.4, upload_mbps=41.0)

    async def cloudflare() -> SpeedResult:
        calls.append("cloudflare")
        return SpeedResult(method="cloudflare", download_mbps=280.0)

    result = await run_speed_cascade([("ookla_bin", ookla), ("cloudflare", cloudflare)])
    assert result.method == "ookla_bin"
    assert result.download_mbps == 312.4
    assert calls == ["ookla"]
    assert [a.tier for a in result.tier_attempts] == ["ookla_bin"]
    assert result.tier_attempts[0].ok is True


async def test_cascade_records_a_failed_tier_and_moves_on():
    async def ookla() -> SpeedResult:
        raise FileNotFoundError("speedtest binary not on PATH")

    async def cloudflare() -> SpeedResult:
        return SpeedResult(method="cloudflare", download_mbps=280.0)

    result = await run_speed_cascade([("ookla_bin", ookla), ("cloudflare", cloudflare)])
    assert result.method == "cloudflare"
    assert [a.tier for a in result.tier_attempts] == ["ookla_bin", "cloudflare"]
    assert result.tier_attempts[0].ok is False
    assert "not on PATH" in result.tier_attempts[0].reason
    assert result.tier_attempts[1].ok is True


async def test_a_tier_that_returns_zero_download_counts_as_a_failure():
    async def dead() -> SpeedResult:
        return SpeedResult(method="cloudflare", download_mbps=0.0)

    async def alive() -> SpeedResult:
        return SpeedResult(method="fastcom", download_mbps=95.0)

    result = await run_speed_cascade([("cloudflare", dead), ("fastcom", alive)])
    assert result.method == "fastcom"
    assert result.tier_attempts[0].ok is False
    assert result.tier_attempts[0].reason == "no throughput measured"


async def test_cascade_exhaustion_is_a_failed_result_not_an_exception():
    async def boom() -> SpeedResult:
        raise OSError("network unreachable")

    result = await run_speed_cascade([("ookla_bin", boom), ("cloudflare", boom), ("fastcom", boom)])
    assert isinstance(result, SpeedResult)
    assert result.method == "none"
    assert result.download_mbps is None
    assert [a.tier for a in result.tier_attempts] == ["ookla_bin", "cloudflare", "fastcom"]
    assert all(a.ok is False for a in result.tier_attempts)


async def test_an_empty_cascade_is_a_failed_result():
    result = await run_speed_cascade([])
    assert result.method == "none"
    assert result.tier_attempts == []


async def test_cascade_never_swallows_cancellation():
    import asyncio

    async def cancelled() -> SpeedResult:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_speed_cascade([("ookla_bin", cancelled)])


def test_the_ndt7_consent_notice_states_what_gets_published():
    assert "CC0" in NDT7_CONSENT_NOTICE
    assert "IP" in NDT7_CONSENT_NOTICE
    assert "public" in NDT7_CONSENT_NOTICE.lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_speed_math.py -q -k "cascade or ndt7"`
Expected: FAIL — `ImportError: cannot import name 'NDT7_CONSENT_NOTICE'`.

- [ ] **Step 3: Append the cascade to `src/netcheck/speed.py`**

```python
import asyncio
import time
from typing import Awaitable, Callable

from netcheck.models import SpeedResult, TierAttempt

NDT7_CONSENT_NOTICE = (
    "M-Lab NDT7 publishes every measurement as public CC0 open data, including your "
    "IP address. Pass --ndt7 only if that is acceptable to you."
)


async def run_speed_cascade(
    tiers: list[tuple[str, Callable[[], Awaitable[SpeedResult]]]],
) -> SpeedResult:
    attempts: list[TierAttempt] = []
    for name, tier in tiers:
        began = time.perf_counter()
        try:
            result = await tier()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - a dead tier is data, not control flow
            attempts.append(
                TierAttempt(
                    tier=name,
                    ok=False,
                    reason=str(exc) or exc.__class__.__name__,
                    duration_ms=int((time.perf_counter() - began) * 1000),
                )
            )
            continue
        duration_ms = int((time.perf_counter() - began) * 1000)
        if not result.download_mbps:
            attempts.append(
                TierAttempt(tier=name, ok=False, reason="no throughput measured", duration_ms=duration_ms)
            )
            continue
        attempts.append(TierAttempt(tier=name, ok=True, reason=None, duration_ms=duration_ms))
        result.tier_attempts = attempts
        return result
    return SpeedResult(method="none", tier_attempts=attempts)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_speed_math.py -q`
Expected: PASS, 20 tests.

- [ ] **Step 5: Append the tier implementations (glue) to `src/netcheck/speed.py`**

```python
import json

import httpx

from netcheck.config import Speedtest


async def tier_ookla(binary: str, server: str | None, timeout: float) -> SpeedResult:
    args = [binary, "--format=json", "--accept-license", "--accept-gdpr"]
    if server:
        args += ["--server-id", server] if server.isdigit() else ["--host", server]
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    payload = json.loads(stdout.decode("utf-8", "replace"))
    download = payload.get("download") or {}
    upload = payload.get("upload") or {}
    server_info = payload.get("server") or {}
    return SpeedResult(
        method="ookla_bin",
        download_mbps=round(mbps(download.get("bytes", 0), (download.get("elapsed", 0) or 0) / 1000), 3),
        upload_mbps=round(mbps(upload.get("bytes", 0), (upload.get("elapsed", 0) or 0) / 1000), 3),
        server=f"{server_info.get('name', '')} ({server_info.get('location', '')})".strip(),
        idle_rtt_ms=(payload.get("ping") or {}).get("latency"),
    )


async def tier_cloudflare(client: httpx.AsyncClient, cfg: Speedtest, timeout: float) -> SpeedResult:
    down_samples: list[tuple[int, float]] = []
    cfl4: CfL4Stats | None = None
    for size in cfg.download_sizes_bytes:
        began = time.perf_counter()
        response = await client.get(
            f"{cfg.cloudflare_base_url}/__down", params={"bytes": size}, timeout=timeout
        )
        response.raise_for_status()
        down_samples.append((len(response.content), time.perf_counter() - began))
        cfl4 = parse_server_timing_cfl4(response.headers.get("server-timing", "")) or cfl4
    up_samples: list[tuple[int, float]] = []
    for size in cfg.upload_sizes_bytes:
        payload = b"\x00" * size
        began = time.perf_counter()
        response = await client.post(f"{cfg.cloudflare_base_url}/__up", content=payload, timeout=timeout)
        response.raise_for_status()
        up_samples.append((size, time.perf_counter() - began))
    return SpeedResult(
        method="cloudflare",
        download_mbps=throughput_from_samples(down_samples),
        upload_mbps=throughput_from_samples(up_samples),
        server="speed.cloudflare.com",
        cfL4_stats=cfl4,
    )


async def tier_fastcom(client: httpx.AsyncClient, cfg: Speedtest, timeout: float) -> SpeedResult:
    response = await client.get(
        cfg.fastcom_api_url,
        params={"https": "true", "token": "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm", "urlCount": "3"},
        timeout=timeout,
    )
    response.raise_for_status()
    targets = response.json().get("targets") or []
    samples: list[tuple[int, float]] = []
    on_net: bool | None = None
    for target in targets:
        url = target.get("url")
        if not url:
            continue
        location = (target.get("location") or {}).get("country")
        on_net = on_net or bool(location)
        began = time.perf_counter()
        body = await client.get(url, timeout=timeout)
        body.raise_for_status()
        samples.append((len(body.content), time.perf_counter() - began))
    return SpeedResult(
        method="fastcom",
        download_mbps=throughput_from_samples(samples),
        upload_mbps=None,
        server=targets[0].get("url", "").split("/")[2] if targets else None,
        netflix_oca_onnet=on_net,
    )


async def tier_ndt7(client: httpx.AsyncClient, cfg: Speedtest, timeout: float) -> SpeedResult:
    import websockets

    locate = await client.get(cfg.ndt7_locate_url, timeout=timeout)
    locate.raise_for_status()
    results = locate.json().get("results") or []
    if not results:
        raise RuntimeError("no ndt7 server offered by locate.measurementlab.net")
    url = results[0]["urls"]["wss:///ndt/v7/download"]
    total = 0
    began = time.perf_counter()
    async with websockets.connect(url, subprotocols=["net.measurementlab.ndt.v7"]) as socket:
        while time.perf_counter() - began < 10:
            try:
                message = await asyncio.wait_for(socket.recv(), timeout=timeout)
            except (asyncio.TimeoutError, Exception):
                break
            total += len(message) if isinstance(message, (bytes, bytearray)) else len(message.encode())
    elapsed = time.perf_counter() - began
    return SpeedResult(
        method="ndt7",
        download_mbps=round(mbps(total, elapsed), 3),
        upload_mbps=None,
        server=results[0].get("machine"),
    )
```

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/speed.py tests/test_speed_math.py
git commit -m "speed: ookla, cloudflare, fast.com and ndt7 cascade tiers"
```

---

### Task 33: `speed.py` — bufferbloat measurement under load

**Files:**
- Modify: `src/netcheck/speed.py` (append)
- Test: `tests/test_speed_math.py` (append)

**Interfaces:**
- Consumes: `bufferbloat_delta` (Task 31), `grade_bufferbloat` (Task 16), `tcp_connect_rtt` (Task 25).
- Produces:
  - `async probe_while(coro: Awaitable[None], probe: Callable[[], Awaitable[float | None]], interval: float) -> list[float]`
  - `async measure_with_bufferbloat(result: SpeedResult, idle_rtt_ms: float | None, bands, run_download, run_upload, probe, interval) -> SpeedResult`

- [ ] **Step 1: Write the failing test (append to `tests/test_speed_math.py`)**

```python
from netcheck.config import BufferbloatBands
from netcheck.speed import measure_with_bufferbloat, probe_while


async def test_probe_while_collects_samples_for_the_whole_duration_of_the_work():
    import asyncio

    async def work() -> None:
        await asyncio.sleep(0.25)

    async def probe() -> float | None:
        return 42.0

    samples = await probe_while(work(), probe, interval=0.05)
    assert len(samples) >= 3
    assert all(s == 42.0 for s in samples)


async def test_probe_while_drops_failed_probes_instead_of_recording_none():
    import asyncio

    async def work() -> None:
        await asyncio.sleep(0.15)

    async def probe() -> float | None:
        return None

    assert await probe_while(work(), probe, interval=0.05) == []


async def test_measure_with_bufferbloat_fills_in_both_directions_and_the_grade():
    import asyncio

    loaded = iter([80.0, 90.0, 100.0] * 20)

    async def run_download() -> None:
        await asyncio.sleep(0.15)

    async def run_upload() -> None:
        await asyncio.sleep(0.15)

    async def probe() -> float | None:
        return next(loaded)

    result = await measure_with_bufferbloat(
        SpeedResult(method="cloudflare", download_mbps=300.0, upload_mbps=40.0),
        idle_rtt_ms=12.0,
        bands=BufferbloatBands(),
        run_download=run_download,
        run_upload=run_upload,
        probe=probe,
        interval=0.05,
    )
    assert result.idle_rtt_ms == 12.0
    assert result.loaded_rtt_down_ms is not None
    assert result.loaded_rtt_up_ms is not None
    assert result.bufferbloat_down_ms is not None and result.bufferbloat_down_ms > 60
    assert result.bufferbloat_grade in ("D", "E", "F")


async def test_measure_with_bufferbloat_without_an_idle_baseline_grades_unknown():
    import asyncio

    async def work() -> None:
        await asyncio.sleep(0.05)

    async def probe() -> float | None:
        return 80.0

    result = await measure_with_bufferbloat(
        SpeedResult(method="cloudflare", download_mbps=300.0),
        idle_rtt_ms=None,
        bands=BufferbloatBands(),
        run_download=work,
        run_upload=work,
        probe=probe,
        interval=0.02,
    )
    assert result.bufferbloat_down_ms is None
    assert result.bufferbloat_grade == "?"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_speed_math.py -q -k bufferbloat`
Expected: FAIL — `ImportError: cannot import name 'probe_while'`.

- [ ] **Step 3: Append the bufferbloat probe to `src/netcheck/speed.py`**

```python
from netcheck.config import BufferbloatBands
from netcheck.interpret import grade_bufferbloat
from netcheck.stats import rtt_stats


async def probe_while(
    coro: Awaitable[None],
    probe: Callable[[], Awaitable[float | None]],
    interval: float,
) -> list[float]:
    samples: list[float] = []
    task = asyncio.ensure_future(coro)
    while not task.done():
        sample = await probe()
        if sample is not None:
            samples.append(sample)
        await asyncio.sleep(interval)
    await task
    return samples


async def measure_with_bufferbloat(
    result: SpeedResult,
    idle_rtt_ms: float | None,
    bands: BufferbloatBands,
    run_download: Callable[[], Awaitable[None]],
    run_upload: Callable[[], Awaitable[None]],
    probe: Callable[[], Awaitable[float | None]],
    interval: float,
) -> SpeedResult:
    # This is the one place a measurement is allowed to overlap another: the
    # whole point is to see what latency does while the link is saturated.
    down_samples = await probe_while(run_download(), probe, interval)
    up_samples = await probe_while(run_upload(), probe, interval)
    result.idle_rtt_ms = idle_rtt_ms
    result.loaded_rtt_down_ms = rtt_stats(list(down_samples)).avg_ms
    result.loaded_rtt_up_ms = rtt_stats(list(up_samples)).avg_ms
    result.bufferbloat_down_ms = bufferbloat_delta(idle_rtt_ms, down_samples)
    result.bufferbloat_up_ms = bufferbloat_delta(idle_rtt_ms, up_samples)
    worst_delta = max(
        [d for d in (result.bufferbloat_down_ms, result.bufferbloat_up_ms) if d is not None],
        default=None,
    )
    result.bufferbloat_grade = grade_bufferbloat(worst_delta, bands)
    return result
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_speed_math.py -q`
Expected: PASS, 24 tests.

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, ~200 tests, no failures.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/speed.py tests/test_speed_math.py
git commit -m "speed: bufferbloat probe running concurrently with saturation"
```

---
## Phase 6 — Export

### Task 34: `exporter.py` — report assembly, strict JSON, atomic writes

**Files:**
- Create: `src/netcheck/exporter.py`
- Test: `tests/test_exporter.py`

**Interfaces:**
- Consumes: `ModuleResult`, `Finding`, `to_jsonable` (Tasks 3–4); `overall_verdict` (Task 16).
- Produces:
  - `SCHEMA_VERSION: int`, `SECTION_ORDER: tuple[str, ...]`
  - `sanitize_name(value: str | None, fallback: str = "unknown") -> str`
  - `compact_timestamp(iso: str) -> str`
  - `report_filename(asn: str | None, started_at: str, extension: str) -> str`
  - `flatten_errors(modules: dict[str, ModuleResult]) -> list[dict]`
  - `build_report(meta: dict, modules: dict[str, ModuleResult], findings: list[Finding], raw: dict) -> dict`
  - `dump_json(report: dict) -> str`
  - `atomic_write(path: Path, text: str) -> Path`
  - `egress_asn(report: dict) -> str | None`
  - `write_report(report: dict, markdown: str, logs_dir: Path) -> tuple[Path, Path]`

**Section data contract** — `cli.py` (Task 37) fills `modules` with exactly these keys, and every renderer below reads them:

| Section | `ModuleResult.data` |
|---|---|
| `connection` | `LocalNet` |
| `ip_geo` | `{"egress_v4": IpGeo, "egress_v6": IpGeo \| None, "cf_trace": CfTrace \| None, "dual_stack_note": str \| None}` |
| `vpn_assessment` | `VpnAssessment` |
| `bgp` | `BgpIntel` |
| `reputation` | `Reputation` |
| `latency` | `list[PingResult]` |
| `path` | `list[TraceResult]` |
| `speed` | `SpeedResult` |

- [ ] **Step 1: Write the failing test**

`tests/test_exporter.py`:

```python
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from netcheck.exporter import (
    SCHEMA_VERSION,
    SECTION_ORDER,
    atomic_write,
    build_report,
    compact_timestamp,
    dump_json,
    egress_asn,
    flatten_errors,
    report_filename,
    sanitize_name,
    write_report,
)
from netcheck.models import (
    Finding,
    IpGeo,
    LocalNet,
    ModuleResult,
    PingResult,
    ProbeError,
    SpeedResult,
)


def meta() -> dict:
    return {
        "run_id": "b7f1",
        "started_at": "2026-08-08T19:12:00Z",
        "finished_at": "2026-08-08T19:13:04Z",
        "mode": "auto",
        "target": None,
        "flags": {"quick": True, "full": False, "dnsbl": False, "ndt7": False, "tcp_trace": False},
        "host_os": "Windows",
        "capabilities": {"os_name": "Windows", "chosen_latency_backend": "icmp_win"},
    }


def modules() -> dict[str, ModuleResult]:
    return {
        "connection": ModuleResult(name="connection", status="ok", data=LocalNet(iface_name="Wi-Fi 2")),
        "ip_geo": ModuleResult(
            name="ip_geo",
            status="ok",
            data={
                "egress_v4": IpGeo(ip="203.0.113.44", asn="AS64500", as_name="Example Telecom"),
                "egress_v6": None,
                "cf_trace": None,
                "dual_stack_note": None,
            },
        ),
        "latency": ModuleResult(
            name="latency",
            status="partial",
            data=[PingResult(label="cloudflare-dns", host="1.1.1.1", method="icmp_win", sent=5, received=5)],
            errors=[ProbeError(source="quad9-dns", kind="timeout", message="2s", retryable=True)],
            warnings=["quad9 did not answer"],
            duration_ms=1500,
        ),
        "speed": ModuleResult(name="speed", status="skipped", data=None),
    }


def test_report_carries_every_top_level_key_from_the_spec():
    report = build_report(meta(), modules(), [], {"ip-api": {"status": "success"}})
    expected = {"schema_version", "meta", "interpretation", "errors", "raw", *SECTION_ORDER}
    assert expected.issubset(report.keys())
    assert report["schema_version"] == SCHEMA_VERSION


def test_missing_modules_are_rendered_as_skipped_sections_not_dropped():
    report = build_report(meta(), modules(), [], {})
    assert report["bgp"]["status"] == "skipped"
    assert report["bgp"]["data"] is None
    assert set(SECTION_ORDER) == {
        "connection",
        "ip_geo",
        "vpn_assessment",
        "bgp",
        "reputation",
        "latency",
        "path",
        "speed",
    }


def test_interpretation_is_computed_from_the_findings():
    findings = [Finding(id="a", severity="warn", title="Jitter high", detail="d")]
    report = build_report(meta(), modules(), findings, {})
    assert report["interpretation"]["overall_status"] == "warn"
    assert report["interpretation"]["overall_score"] == 90
    assert report["interpretation"]["findings"][0]["id"] == "a"


def test_errors_are_flattened_to_the_top_level_with_their_module():
    flat = flatten_errors(modules())
    assert flat == [
        {
            "source": "quad9-dns",
            "kind": "timeout",
            "message": "2s",
            "retryable": True,
            "module": "latency",
        }
    ]


def test_raw_payloads_are_stored_verbatim_under_their_source_key():
    raw = {"ip-api": {"status": "success", "as": "AS64500 Example"}, "cf-trace": "ip=203.0.113.44"}
    report = build_report(meta(), modules(), [], raw)
    assert report["raw"]["ip-api"]["as"] == "AS64500 Example"
    assert report["raw"]["cf-trace"] == "ip=203.0.113.44"


def test_non_finite_numbers_that_reached_the_pipeline_serialize_as_null():
    # Zero-duration timing math produces exactly this on the failure paths the
    # report most needs to show; allow_nan=False would otherwise abort the write.
    broken = modules()
    broken["speed"] = ModuleResult(
        name="speed",
        status="partial",
        data=SpeedResult(
            method="cloudflare",
            download_mbps=float("inf"),
            upload_mbps=float("nan"),
            idle_rtt_ms=float("-inf"),
            bufferbloat_down_ms=12.5,
        ),
    )
    report = build_report(meta(), broken, [], {"cloudflare": {"rate": float("inf")}})
    text = dump_json(report)
    back = json.loads(text)
    assert back["speed"]["data"]["download_mbps"] is None
    assert back["speed"]["data"]["upload_mbps"] is None
    assert back["speed"]["data"]["idle_rtt_ms"] is None
    assert back["speed"]["data"]["bufferbloat_down_ms"] == 12.5
    assert back["raw"]["cloudflare"]["rate"] is None
    assert "Infinity" not in text
    assert "NaN" not in text


def test_dump_json_is_strict_and_round_trips():
    report = build_report(meta(), modules(), [], {})
    back = json.loads(dump_json(report))
    assert back["meta"]["run_id"] == "b7f1"
    assert back["latency"]["data"][0]["label"] == "cloudflare-dns"
    assert math.isfinite(back["latency"]["duration_ms"])


def test_compact_timestamp_strips_the_characters_windows_forbids():
    assert compact_timestamp("2026-08-08T19:12:00Z") == "20260808T191200Z"
    assert compact_timestamp("") == "unknown"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AS64500", "AS64500"),
        ("AS64500 Example Telecom", "AS64500_Example_Telecom"),
        ("AS64500/../etc", "AS64500_.._etc"),
        ("AS:64500", "AS_64500"),
        ("", "unknown"),
        (None, "unknown"),
        ("///", "unknown"),
    ],
)
def test_sanitize_name_produces_windows_safe_fragments(value, expected):
    assert sanitize_name(value) == expected


def test_report_filename_matches_the_documented_pattern():
    assert (
        report_filename("AS64500", "2026-08-08T19:12:00Z", "json")
        == "report_AS64500_20260808T191200Z.json"
    )
    assert (
        report_filename(None, "2026-08-08T19:12:00Z", "md")
        == "report_unknown_20260808T191200Z.md"
    )


def test_egress_asn_is_read_out_of_the_assembled_report():
    report = build_report(meta(), modules(), [], {})
    assert egress_asn(report) == "AS64500"
    assert egress_asn({"ip_geo": {"data": None}}) is None
    assert egress_asn({}) is None


def test_atomic_write_creates_the_directory_and_leaves_no_temp_file(tmp_path: Path):
    target = tmp_path / "logs" / "report.json"
    atomic_write(target, '{"a": 1}')
    assert target.read_text(encoding="utf-8") == '{"a": 1}'
    assert list((tmp_path / "logs").iterdir()) == [target]


def test_atomic_write_replaces_an_existing_file(tmp_path: Path):
    target = tmp_path / "report.json"
    atomic_write(target, "old")
    atomic_write(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert not list(tmp_path.glob("*.tmp"))


def test_write_report_emits_both_artifacts_with_matching_names(tmp_path: Path):
    report = build_report(meta(), modules(), [], {})
    json_path, md_path = write_report(report, "# netcheck report\n", tmp_path)
    assert json_path.name == "report_AS64500_20260808T191200Z.json"
    assert md_path.name == "report_AS64500_20260808T191200Z.md"
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema_version"] == SCHEMA_VERSION
    assert md_path.read_text(encoding="utf-8").startswith("# netcheck report")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_exporter.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.exporter'`.

- [ ] **Step 3: Implement the JSON layer in `src/netcheck/exporter.py`**

```python
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from netcheck.interpret import overall_verdict
from netcheck.models import Finding, ModuleResult, to_jsonable

SCHEMA_VERSION = 1
SECTION_ORDER = (
    "connection",
    "ip_geo",
    "vpn_assessment",
    "bgp",
    "reputation",
    "latency",
    "path",
    "speed",
)

_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_name(value: str | None, fallback: str = "unknown") -> str:
    cleaned = _UNSAFE_NAME_RE.sub("_", (value or "").strip()).strip("._")
    return cleaned[:32] or fallback


def compact_timestamp(iso: str) -> str:
    # Windows forbids ':' in filenames, so the stamp is the compact ISO form.
    return re.sub(r"[-:]", "", (iso or "").strip()) or "unknown"


def report_filename(asn: str | None, started_at: str, extension: str) -> str:
    return f"report_{sanitize_name(asn)}_{compact_timestamp(started_at)}.{extension.lstrip('.')}"


def flatten_errors(modules: dict[str, ModuleResult]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for section, result in modules.items():
        for error in result.errors:
            entry = to_jsonable(error)
            entry["module"] = result.name or section
            flat.append(entry)
    return flat


def build_report(
    meta: dict[str, Any],
    modules: dict[str, ModuleResult],
    findings: list[Finding],
    raw: dict[str, Any],
) -> dict[str, Any]:
    status, score, summary = overall_verdict(findings)
    report: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "meta": to_jsonable(meta)}
    for section in SECTION_ORDER:
        result = modules.get(section) or ModuleResult(name=section, status="skipped")
        report[section] = to_jsonable(result)
    report["interpretation"] = {
        "overall_status": status,
        "overall_score": score,
        "summary_text": summary,
        "findings": to_jsonable(findings),
    }
    report["errors"] = flatten_errors(modules)
    report["raw"] = to_jsonable(raw)
    return report


def dump_json(report: dict[str, Any]) -> str:
    return json.dumps(to_jsonable(report), allow_nan=False, ensure_ascii=False, indent=2)


def atomic_write(path: Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def egress_asn(report: dict[str, Any]) -> str | None:
    data = (report.get("ip_geo") or {}).get("data") or {}
    return ((data.get("egress_v4") or {}) if isinstance(data, dict) else {}).get("asn")


def write_report(report: dict[str, Any], markdown: str, logs_dir: Path) -> tuple[Path, Path]:
    started = (report.get("meta") or {}).get("started_at", "")
    asn = egress_asn(report)
    base = Path(logs_dir)
    json_path = atomic_write(base / report_filename(asn, started, "json"), dump_json(report))
    md_path = atomic_write(base / report_filename(asn, started, "md"), markdown)
    return json_path, md_path
```

`to_jsonable` already coerces `inf`/`NaN` to `null` (Task 3), so `allow_nan=False` here is a *guard* rather than the mechanism: if a future change slips a raw float past the coercion, the write fails loudly instead of emitting `Infinity`, which is not valid JSON for any other reader.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_exporter.py -q`
Expected: PASS, 21 tests.

- [ ] **Step 5: Commit**

```bash
git add src/netcheck/exporter.py tests/test_exporter.py
git commit -m "exporter: report assembly, strict json and atomic writes"
```

---

### Task 35: `exporter.py` — sparkline and Markdown rendering

**Files:**
- Modify: `src/netcheck/exporter.py` (append)
- Test: `tests/test_exporter.py` (append)

**Interfaces:**
- Consumes: Task 34's `SECTION_ORDER`; `bufferbloat_consequence` (Task 16).
- Produces:
  - `SPARK_CHARS: str`
  - `sparkline(values: list[float | None]) -> str`
  - `badge(severity: str, emoji: bool) -> str`
  - `first_loss_jump(hops: list[dict]) -> int | None`
  - `render_markdown(report: dict, emoji: bool = True) -> str`

The sparkline is ~15 lines inline (spec §14) — a dependency for five glyphs would be absurd. `render_markdown` reads the *assembled report dict*, not the typed objects: that is the same shape `compare.py` (Task 38) loads from disk, so both renderers see one contract and a rendering bug shows up identically for a fresh run and a saved one.

- [ ] **Step 1: Write the failing test (append to `tests/test_exporter.py`)**

```python
from netcheck.exporter import SPARK_CHARS, badge, first_loss_jump, render_markdown, sparkline
from netcheck.models import (
    AdapterLeakResult,
    BgpIntel,
    CfTrace,
    DnsLeak,
    DnsblHit,
    InternetDbResult,
    IxpPresence,
    Reputation,
    Signal,
    TierAttempt,
    TraceHop,
    TraceResult,
    VpnAssessment,
)


def full_modules() -> dict[str, ModuleResult]:
    return {
        "connection": ModuleResult(
            name="connection",
            status="ok",
            data=LocalNet(
                iface_name="Wi-Fi 2",
                local_ipv4="192.168.1.34",
                iface_mtu=1500,
                default_gateway_v4="192.168.1.1",
                dns_servers_per_adapter={"Wi-Fi 2": ["192.168.1.1"]},
            ),
        ),
        "ip_geo": ModuleResult(
            name="ip_geo",
            status="ok",
            data={
                "egress_v4": IpGeo(
                    ip="203.0.113.44",
                    asn="AS64500",
                    as_name="Example Telecom",
                    city="Amsterdam",
                    country="Netherlands",
                    country_code="NL",
                    ip_type="residential",
                    reverse_dns="host-203-0-113-44.example.net",
                ),
                "egress_v6": IpGeo(ip="2001:db8::1", asn="AS64500"),
                "cf_trace": CfTrace(ip="203.0.113.44", colo="AMS", warp="off"),
                "dual_stack_note": None,
            },
        ),
        "vpn_assessment": ModuleResult(
            name="vpn_assessment",
            status="ok",
            data=VpnAssessment(
                verdict="likely",
                confidence=0.55,
                signals=[Signal(name="cf_warp", observed=True, weight=0.5, direction="vpn", note="on")],
                tunnel_iface="wg0",
                dns_leak=DnsLeak(
                    per_adapter=[
                        AdapterLeakResult(
                            adapter="Wi-Fi 2",
                            configured_resolvers=["192.168.1.1"],
                            echoed_ip="203.0.113.9",
                            echoed_asn="AS64501",
                            matches_egress_asn=False,
                        )
                    ],
                    ecs_leaked=True,
                    note="ISP resolver still active on the Wi-Fi adapter.",
                ),
            ),
        ),
        "bgp": ModuleResult(
            name="bgp",
            status="ok",
            data=BgpIntel(
                asn="AS64500",
                holder="Example Telecom BV",
                upstreams=["AS3356"],
                prefix_count_v4=2,
                prefix_count_v6=1,
                stability="stable",
                ixps=[IxpPresence(name="AMS-IX", city="Amsterdam", country="NL", speed_mbps=100000)],
                asrank=1842,
                cone_asns=37,
                pdb_info_type="Cable/DSL/ISP",
            ),
        ),
        "reputation": ModuleResult(
            name="reputation",
            status="ok",
            data=Reputation(
                internetdb=InternetDbResult(ip="203.0.113.44", ports=[80, 443], tags=["cdn"]),
                firehol_hits=[],
                dnsbl_hits=[DnsblHit(zone="bl.spamcop.net", codes=["127.0.0.2"])],
                dnsbl_query_blocked=True,
                captcha_risk="high",
                rationale="listed on bl.spamcop.net",
            ),
        ),
        "latency": ModuleResult(
            name="latency",
            status="ok",
            data=[
                PingResult(
                    label="cloudflare-dns",
                    host="1.1.1.1",
                    method="icmp_win",
                    sent=5,
                    received=5,
                    avg_ms=12.4,
                    min_ms=11.0,
                    max_ms=15.1,
                    jitter_ms=1.9,
                    samples=[11.0, 12.0, None, 15.1, 12.4],
                ),
                PingResult(label="github", host="github.com", method="tcp", sent=5, received=4, loss_pct=20.0, avg_ms=42.0),
            ],
            duration_ms=2400,
        ),
        "path": ModuleResult(
            name="path",
            status="ok",
            data=[
                TraceResult(
                    target="1.1.1.1",
                    backend="icmp_win",
                    completed=True,
                    hops=[
                        TraceHop(ttl=1, ip="192.168.1.1", avg_ms=1.1, loss_pct=0.0),
                        TraceHop(ttl=2, ip="10.64.0.1", avg_ms=9.0, loss_pct=60.0),
                        TraceHop(ttl=3, ip="1.1.1.1", avg_ms=12.4, loss_pct=55.0),
                    ],
                )
            ],
        ),
        "speed": ModuleResult(
            name="speed",
            status="ok",
            data=SpeedResult(
                method="cloudflare",
                tier_attempts=[
                    TierAttempt(tier="ookla_bin", ok=False, reason="binary not on PATH"),
                    TierAttempt(tier="cloudflare", ok=True),
                ],
                download_mbps=284.3,
                upload_mbps=41.7,
                server="speed.cloudflare.com",
                idle_rtt_ms=12.0,
                loaded_rtt_down_ms=48.0,
                bufferbloat_down_ms=36.0,
                bufferbloat_grade="C",
            ),
        ),
    }


def full_report() -> dict:
    findings = [
        Finding(
            id="latency.loss.github",
            severity="warn",
            title="Loss to github.com",
            detail="20.0% connection failures over 5 probes via tcp.",
            metric="loss_pct",
            value=20.0,
            threshold=2.0,
            advice="Sustained loss on every host points at the local link.",
        )
    ]
    return build_report(meta(), full_modules(), findings, {"ip-api": {"status": "success"}})


def test_sparkline_maps_a_series_across_the_glyph_ramp():
    line = sparkline([1.0, 2.0, 3.0, 4.0, 5.0])
    assert len(line) == 5
    assert line[0] == SPARK_CHARS[0]
    assert line[-1] == SPARK_CHARS[-1]
    assert SPARK_CHARS == "▁▂▃▅▇"


def test_sparkline_of_a_flat_series_is_all_baseline():
    assert sparkline([7.0, 7.0, 7.0]) == SPARK_CHARS[0] * 3


def test_sparkline_renders_a_dropped_probe_as_a_gap():
    line = sparkline([1.0, None, 5.0])
    assert line[1] == " "
    assert len(line) == 3


def test_sparkline_of_nothing_is_empty():
    assert sparkline([]) == ""
    assert sparkline([None, None]) == ""


def test_badge_is_gated_behind_the_emoji_setting():
    assert badge("crit", emoji=True) == "🔴"
    assert badge("warn", emoji=True) == "🟡"
    assert badge("ok", emoji=True) == "🟢"
    assert badge("crit", emoji=False) == "[crit]"
    assert badge("warn", emoji=False) == "[warn]"


def test_first_loss_jump_needs_the_loss_to_persist_downstream():
    hops = [
        {"ttl": 1, "loss_pct": 0.0},
        {"ttl": 2, "loss_pct": 60.0},
        {"ttl": 3, "loss_pct": 55.0},
    ]
    assert first_loss_jump(hops) == 2


def test_first_loss_jump_ignores_a_single_icmp_rate_limiting_hop():
    hops = [{"ttl": 1, "loss_pct": 0.0}, {"ttl": 2, "loss_pct": 100.0}, {"ttl": 3, "loss_pct": 0.0}]
    assert first_loss_jump(hops) is None
    assert first_loss_jump([]) is None


def test_markdown_has_every_section_from_the_spec_in_order():
    text = render_markdown(full_report())
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == [
        "## TL;DR",
        "## Connection & identity",
        "## VPN / proxy assessment",
        "## ASN & BGP intelligence",
        "## Reputation",
        "## Latency",
        "## Path",
        "## Speed",
        "## Problems & recommendations",
        "## Run diagnostics",
    ]
    assert text.startswith("# netcheck report")


def test_markdown_header_states_mode_timestamp_and_verdict():
    text = render_markdown(full_report())
    assert "auto" in text
    assert "2026-08-08T19:12:00Z" in text
    assert "90/100" in text


def test_markdown_reports_identity_and_both_stacks():
    text = render_markdown(full_report())
    assert "203.0.113.44" in text
    assert "AS64500" in text
    assert "2001:db8::1" in text
    assert "Amsterdam" in text
    assert "residential" in text


def test_markdown_vpn_section_lists_signals_and_the_dns_leak():
    text = render_markdown(full_report())
    assert "likely" in text
    assert "cf_warp" in text
    assert "Wi-Fi 2" in text
    assert "AS64501" in text
    assert "ISP resolver still active" in text


def test_markdown_dnsbl_error_range_is_never_shown_as_a_plain_listing():
    text = render_markdown(full_report())
    assert "bl.spamcop.net" in text
    assert "not a listing" in text


def test_markdown_latency_table_carries_a_sparkline_in_a_fenced_block():
    text = render_markdown(full_report())
    assert "cloudflare-dns" in text
    assert any(char in text for char in SPARK_CHARS)
    assert text.count("```") >= 2


def test_markdown_flags_that_tcp_loss_is_a_different_metric():
    text = render_markdown(full_report())
    assert "failed TCP connections" in text


def test_markdown_path_section_marks_the_first_loss_jump():
    text = render_markdown(full_report())
    path_block = text.split("## Path")[1].split("## Speed")[0]
    marked = [line for line in path_block.splitlines() if line.rstrip().endswith("<<")]
    assert len(marked) == 1
    assert "10.64.0.1" in marked[0]


def test_markdown_speed_section_explains_the_bufferbloat_grade_in_plain_language():
    text = render_markdown(full_report())
    assert "284.3" in text
    assert "grade C" in text
    assert "choppy" in text
    assert "ookla_bin" in text
    assert "binary not on PATH" in text


def test_markdown_run_diagnostics_lists_every_module_with_its_status():
    text = render_markdown(full_report())
    block = text.split("## Run diagnostics")[1]
    for section in SECTION_ORDER:
        assert section in block


def test_markdown_without_emoji_uses_text_badges():
    text = render_markdown(full_report(), emoji=False)
    assert "[warn]" in text
    assert "🟡" not in text
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_exporter.py -q -k "sparkline or markdown or badge or loss_jump"`
Expected: FAIL — `ImportError: cannot import name 'sparkline' from 'netcheck.exporter'`.

- [ ] **Step 3: Append the renderer to `src/netcheck/exporter.py`**

```python
from netcheck.interpret import bufferbloat_consequence

SPARK_CHARS = "▁▂▃▅▇"
_BADGES = {"ok": "🟢", "info": "🟢", "warn": "🟡", "crit": "🔴"}
_SEVERITY_RANK = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
_LOSS_JUMP_PCT = 20.0


def sparkline(values: list[float | None]) -> str:
    numbers = [v for v in values if v is not None]
    if not numbers:
        return ""
    low, high = min(numbers), max(numbers)
    span = high - low
    out: list[str] = []
    for value in values:
        if value is None:
            out.append(" ")
        elif span <= 0:
            out.append(SPARK_CHARS[0])
        else:
            index = int((value - low) / span * (len(SPARK_CHARS) - 1))
            out.append(SPARK_CHARS[index])
    return "".join(out)


def badge(severity: str, emoji: bool) -> str:
    return _BADGES.get(severity, "⚪") if emoji else f"[{severity}]"


def first_loss_jump(hops: list[dict]) -> int | None:
    for index, hop in enumerate(hops[:-1]):
        following = hops[index + 1]
        if hop.get("loss_pct", 0.0) >= _LOSS_JUMP_PCT and following.get("loss_pct", 0.0) >= _LOSS_JUMP_PCT:
            return hop.get("ttl")
    return None


def _module(report: dict, section: str) -> dict:
    return report.get(section) or {}


def _data(report: dict, section: str) -> Any:
    return _module(report, section).get("data")


def _num(value: Any) -> str:
    return "—" if value is None else f"{value:g}" if isinstance(value, (int, float)) else str(value)


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_No rows._"]
    return (
        ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
        + ["| " + " | ".join(row) + " |" for row in rows]
    )


def _header(report: dict, emoji: bool) -> list[str]:
    meta = report.get("meta") or {}
    interp = report.get("interpretation") or {}
    target = f" · target `{meta.get('target')}`" if meta.get("target") else ""
    status = interp.get("overall_status", "ok")
    return [
        "# netcheck report",
        "",
        f"- Mode: `{meta.get('mode', 'auto')}`{target}",
        f"- Started: {meta.get('started_at', '?')} · finished: {meta.get('finished_at', '?')}",
        f"- Host OS: {meta.get('host_os', '?')} · run id `{meta.get('run_id', '?')}`",
        f"- Verdict: {badge(status, emoji)} **{status}** ({interp.get('overall_score', 0)}/100) — "
        f"{interp.get('summary_text', '')}",
        "",
    ]


def _findings(report: dict) -> list[dict]:
    return sorted(
        (report.get("interpretation") or {}).get("findings") or [],
        key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 9),
    )


def _tldr(report: dict, emoji: bool) -> list[str]:
    found = _findings(report)
    if not found:
        return ["## TL;DR", "", "No problems found on this connection.", ""]
    return ["## TL;DR", ""] + [
        f"- {badge(f.get('severity', 'info'), emoji)} **{f.get('title', '')}** — {f.get('detail', '')}"
        for f in found[:5]
    ] + [""]


def _connection(report: dict) -> list[str]:
    local = _data(report, "connection") or {}
    geo_bundle = _data(report, "ip_geo") or {}
    geo = geo_bundle.get("egress_v4") or {}
    v6 = geo_bundle.get("egress_v6") or {}
    cf = geo_bundle.get("cf_trace") or {}
    rows = [
        ["Interface", f"{local.get('iface_name') or '?'} (MTU {local.get('iface_mtu') or '?'})"],
        ["Local address", f"{local.get('local_ipv4') or '?'} / {local.get('local_ipv6') or '—'}"],
        ["Default gateway", local.get("default_gateway_v4") or "?"],
        ["Egress IPv4", f"{geo.get('ip') or '?'} ({geo.get('asn') or '?'} {geo.get('as_name') or geo.get('org') or ''})"],
        ["Egress IPv6", f"{v6.get('ip') or '—'} ({v6.get('asn') or '—'})"],
        ["Reverse DNS", geo.get("reverse_dns") or "—"],
        ["Location", f"{geo.get('city') or '?'}, {geo.get('country') or geo.get('country_code') or '?'}"],
        ["Address type", geo.get("ip_type") or "unknown"],
        ["Cloudflare colo", cf.get("colo") or "—"],
    ]
    lines = ["## Connection & identity", ""] + _table(["Field", "Value"], rows) + [""]
    if geo_bundle.get("dual_stack_note"):
        lines += [f"> {geo_bundle['dual_stack_note']}", ""]
    return lines


def _vpn(report: dict) -> list[str]:
    vpn = _data(report, "vpn_assessment") or {}
    lines = [
        "## VPN / proxy assessment",
        "",
        f"Verdict: **{vpn.get('verdict', 'unknown')}** · confidence {vpn.get('confidence', 0)}"
        f" · tunnel interface {vpn.get('tunnel_iface') or '—'}",
        "",
    ]
    lines += _table(
        ["Signal", "Observed", "Weight", "Direction", "Note"],
        [
            [
                s.get("name", ""),
                "yes" if s.get("observed") else "no",
                _num(s.get("weight")),
                s.get("direction", ""),
                s.get("note") or "—",
            ]
            for s in vpn.get("signals") or []
        ],
    )
    leak = vpn.get("dns_leak") or {}
    if leak:
        lines += ["", "### DNS leak", ""]
        lines += _table(
            ["Adapter", "Configured resolvers", "Echoed IP", "Echoed ASN", "Same ASN as egress"],
            [
                [
                    a.get("adapter", ""),
                    ", ".join(a.get("configured_resolvers") or []) or "—",
                    a.get("echoed_ip") or "—",
                    a.get("echoed_asn") or "—",
                    {True: "yes", False: "no", None: "?"}[a.get("matches_egress_asn")],
                ]
                for a in leak.get("per_adapter") or []
            ],
        )
        lines += ["", f"EDNS Client Subnet leaked: {'yes' if leak.get('ecs_leaked') else 'no'}", "", leak.get("note", "")]
    return lines + [""]


def _bgp(report: dict) -> list[str]:
    bgp = _data(report, "bgp") or {}
    rows = [
        ["ASN", f"{bgp.get('asn') or '?'} — {bgp.get('holder') or '?'}"],
        ["Registry", f"{bgp.get('registry') or '?'} (allocated {bgp.get('allocated_at') or '?'})"],
        ["Upstreams", ", ".join(bgp.get("upstreams") or []) or "—"],
        ["Peers", ", ".join(bgp.get("peers") or []) or "—"],
        ["Downstreams", ", ".join((bgp.get("downstreams") or [])[:10]) or "—"],
        ["Announced prefixes", f"{bgp.get('prefix_count_v4', 0)} IPv4 / {bgp.get('prefix_count_v6', 0)} IPv6"],
        ["Route stability", f"{bgp.get('stability', 'unknown')} ({len(bgp.get('flaps') or [])} updates in window)"],
        ["CAIDA ASRank", f"#{_num(bgp.get('asrank'))} · cone {_num(bgp.get('cone_asns'))} ASNs / "
                         f"{_num(bgp.get('cone_prefixes'))} prefixes"],
        ["PeeringDB", f"{bgp.get('pdb_info_type') or '—'} · {bgp.get('pdb_traffic') or '—'}"],
    ]
    lines = ["## ASN & BGP intelligence", ""] + _table(["Field", "Value"], rows)
    ixps = bgp.get("ixps") or []
    if ixps:
        lines += ["", "### IXP presence", ""]
        lines += _table(
            ["Exchange", "City", "Country", "Speed (Mbps)"],
            [[i.get("name", ""), i.get("city") or "—", i.get("country") or "—", _num(i.get("speed_mbps"))] for i in ixps],
        )
    return lines + [""]


def _reputation(report: dict) -> list[str]:
    rep = _data(report, "reputation") or {}
    idb = rep.get("internetdb") or {}
    rows = [
        ["FireHOL hits", ", ".join(rep.get("firehol_hits") or []) or "none"],
        ["Open ports (InternetDB)", ", ".join(str(p) for p in idb.get("ports") or []) or "none"],
        ["Tags", ", ".join(idb.get("tags") or []) or "none"],
        ["Known CVEs", ", ".join(idb.get("vulns") or []) or "none"],
        ["AbuseIPDB", _num(rep.get("abuseipdb_score")) if rep.get("abuseipdb_score") is not None else "not queried"],
    ]
    hits = rep.get("dnsbl_hits")
    if hits is None:
        rows.append(["DNSBL", "not run (pass --dnsbl)"])
    else:
        listed = ", ".join(h.get("zone", "") for h in hits) or "no listing"
        if rep.get("dnsbl_query_blocked"):
            listed += " · one or more zones answered with their query-error range, which is not a listing"
        rows.append(["DNSBL", listed])
    return (
        ["## Reputation", "", f"Captcha/blocklist risk: **{rep.get('captcha_risk', 'unknown')}** — "
                              f"{rep.get('rationale', '')}", ""]
        + _table(["Field", "Value"], rows)
        + [""]
    )


def _latency(report: dict) -> list[str]:
    pings = _data(report, "latency") or []
    lines = ["## Latency", ""] + _table(
        ["Host", "Address", "Method", "Avg ms", "Min", "Max", "Jitter", "Loss"],
        [
            [
                p.get("label", ""),
                p.get("host", ""),
                p.get("method", ""),
                _num(p.get("avg_ms")),
                _num(p.get("min_ms")),
                _num(p.get("max_ms")),
                _num(p.get("jitter_ms")),
                f"{p.get('loss_pct', 0)}%",
            ]
            for p in pings
        ],
    )
    if pings:
        lines += ["", "```"]
        lines += [f"{p.get('label', ''):<18}{sparkline(p.get('samples') or [])}" for p in pings]
        lines += ["```"]
    if any(p.get("method") == "tcp" for p in pings):
        lines += ["", "> Loss on a `tcp` row counts failed TCP connections, not dropped ICMP packets."]
    return lines + [""]


def _bar(value: Any) -> str:
    return "#" * int(min(float(value or 0.0), 200.0) / 10)


def _path(report: dict) -> list[str]:
    traces = _data(report, "path") or []
    lines = ["## Path", ""]
    for trace in traces:
        hops = trace.get("hops") or []
        jump = first_loss_jump(hops)
        lines += [
            f"### {trace.get('target') or '?'} — backend `{trace.get('backend', 'none')}`, "
            f"{'complete' if trace.get('completed') else 'incomplete'}",
            "",
            "```",
        ]
        for hop in hops:
            marker = " <<" if jump is not None and hop.get("ttl") == jump else ""
            lines.append(
                f"{hop.get('ttl', 0):>3}  {(hop.get('ip') or '*'):<39} "
                f"{_num(hop.get('avg_ms')):>8} ms  {hop.get('loss_pct', 0):>5}%  {_bar(hop.get('avg_ms'))}{marker}"
            )
        lines += ["```", ""]
    return lines


def _speed(report: dict) -> list[str]:
    speed = _data(report, "speed") or {}
    grade = speed.get("bufferbloat_grade") or "?"
    rows = [
        ["Method", speed.get("method", "none")],
        ["Server", speed.get("server") or "—"],
        ["Download", f"{_num(speed.get('download_mbps'))} Mbps"],
        ["Upload", f"{_num(speed.get('upload_mbps'))} Mbps"],
        ["Idle RTT", f"{_num(speed.get('idle_rtt_ms'))} ms"],
        ["Loaded RTT (down / up)", f"{_num(speed.get('loaded_rtt_down_ms'))} / {_num(speed.get('loaded_rtt_up_ms'))} ms"],
        ["Bufferbloat", f"grade {grade} — down +{_num(speed.get('bufferbloat_down_ms'))} ms, "
                        f"up +{_num(speed.get('bufferbloat_up_ms'))} ms"],
        ["Netflix OCA on-net", {True: "yes", False: "no", None: "—"}[speed.get("netflix_oca_onnet")]],
    ]
    lines = ["## Speed", ""] + _table(["Field", "Value"], rows) + ["", bufferbloat_consequence(grade)]
    attempts = speed.get("tier_attempts") or []
    if attempts:
        lines += ["", "### Cascade", ""]
        lines += _table(
            ["Tier", "Used", "Reason", "ms"],
            [
                [a.get("tier", ""), "yes" if a.get("ok") else "no", a.get("reason") or "—", _num(a.get("duration_ms"))]
                for a in attempts
            ],
        )
    return lines + [""]


def _problems(report: dict, emoji: bool) -> list[str]:
    found = _findings(report)
    if not found:
        return ["## Problems & recommendations", "", "Nothing to act on.", ""]
    lines = ["## Problems & recommendations", ""]
    for f in found:
        lines.append(f"- {badge(f.get('severity', 'info'), emoji)} **{f.get('title', '')}** — {f.get('detail', '')}")
        if f.get("advice"):
            lines.append(f"  - {f['advice']}")
    return lines + [""]


def _diagnostics(report: dict) -> list[str]:
    rows = []
    warnings: list[str] = []
    for section in SECTION_ORDER:
        module = _module(report, section)
        errors = "; ".join(f"{e.get('source')}: {e.get('kind')}" for e in module.get("errors") or []) or "—"
        rows.append([section, module.get("status", "skipped"), _num(module.get("duration_ms")), errors])
        warnings += list(module.get("warnings") or [])
    lines = ["## Run diagnostics", ""] + _table(["Module", "Status", "ms", "Errors"], rows)
    if warnings:
        lines += [""] + [f"- {w}" for w in warnings]
    return lines + [""]


def render_markdown(report: dict[str, Any], emoji: bool = True) -> str:
    lines = _header(report, emoji)
    lines += _tldr(report, emoji)
    lines += _connection(report)
    lines += _vpn(report)
    lines += _bgp(report)
    lines += _reputation(report)
    lines += _latency(report)
    lines += _path(report)
    lines += _speed(report)
    lines += _problems(report, emoji)
    lines += _diagnostics(report)
    return "\n".join(lines).rstrip() + "\n"
```

Every ASCII graph lives inside a fenced block so `rich.markdown.Markdown` cannot reflow it (spec §14).

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_exporter.py -q`
Expected: PASS, 39 tests.

- [ ] **Step 5: Check the module size against the project's 200-line rule**

Run: `uv run python -c "print(sum(1 for _ in open('src/netcheck/exporter.py', encoding='utf-8')))"`
Expected: a number in the 330–380 range. This module is knowingly over the ~200-line guideline: it is one responsibility (rendering the report) expressed as a dozen ten-line section functions, and splitting the Markdown half into a second file would put the two output formats out of sync the first time a field is added. Record that decision in `ARCHITECTURE.md`'s directory-layout entry for `exporter.py` (one clause, e.g. "JSON and Markdown rendering — deliberately over the file-size guideline to keep both formats in one place"), so Task 41 does not "fix" it.

- [ ] **Step 6: Commit**

```bash
git add src/netcheck/exporter.py tests/test_exporter.py ARCHITECTURE.md ARCHITECTURE.ru.md
git commit -m "exporter: markdown rendering with sparklines and hop bars"
```

---

### Task 36: `exporter.py` — a fully failed run still produces a complete report

**Files:**
- Modify: `src/netcheck/exporter.py` (append + rewire the section renderers)
- Test: `tests/test_exporter.py` (append)

**Interfaces:**
- Consumes: Tasks 34–35.
- Produces: `unavailable(report: dict, section: str) -> str | None`, used as the first statement of every section renderer.

This is the spec §11 rule with teeth: *a report missing its speed section must not be indistinguishable from a report where speed was fine*. Task 35's renderers read `.get()` off `data` and quietly emit empty tables when a module failed; this task replaces that silence with an explicit, per-section placeholder that names the status and the error.

- [ ] **Step 1: Write the failing test (append to `tests/test_exporter.py`)**

```python
from netcheck.exporter import unavailable


def dead_modules() -> dict[str, ModuleResult]:
    return {
        section: ModuleResult(
            name=section,
            status="failed",
            data=None,
            errors=[ProbeError(source=section, kind="unavailable", message="network unreachable", retryable=True)],
            duration_ms=8000,
        )
        for section in SECTION_ORDER
    }


def dead_report() -> dict:
    return build_report(meta(), dead_modules(), [], {})


def test_unavailable_describes_a_failed_module_and_stays_quiet_on_a_healthy_one():
    assert unavailable(full_report(), "bgp") is None
    note = unavailable(dead_report(), "bgp")
    assert note is not None
    assert "failed" in note
    assert "network unreachable" in note


def test_unavailable_explains_a_skipped_module_without_inventing_an_error():
    report = build_report(meta(), {"speed": ModuleResult(name="speed", status="skipped")}, [], {})
    note = unavailable(report, "speed")
    assert note is not None
    assert "skipped" in note


def test_an_all_modules_failed_run_still_renders_every_section():
    text = render_markdown(dead_report())
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert len(headings) == 10
    assert text.count("Not available") == 8


def test_an_all_modules_failed_report_is_still_valid_strict_json():
    report = dead_report()
    back = json.loads(dump_json(report))
    assert back["schema_version"] == SCHEMA_VERSION
    assert len(back["errors"]) == len(SECTION_ORDER)
    assert all(section in back for section in SECTION_ORDER)
    assert back["interpretation"]["overall_status"] == "ok"
    assert back["raw"] == {}


def test_an_all_modules_failed_run_writes_both_artifacts(tmp_path: Path):
    report = dead_report()
    json_path, md_path = write_report(report, render_markdown(report), tmp_path)
    assert json_path.name.startswith("report_unknown_")
    assert md_path.name.startswith("report_unknown_")
    assert "## Run diagnostics" in md_path.read_text(encoding="utf-8")


def test_the_diagnostics_table_still_names_every_failed_module():
    block = render_markdown(dead_report()).split("## Run diagnostics")[1]
    assert block.count("failed") == len(SECTION_ORDER)
    assert "unavailable" in block


def test_a_partial_module_with_data_is_rendered_normally_not_as_a_placeholder():
    report = build_report(meta(), modules(), [], {})
    assert unavailable(report, "latency") is None
    assert "cloudflare-dns" in render_markdown(report)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_exporter.py -q -k "unavailable or failed"`
Expected: FAIL — `ImportError: cannot import name 'unavailable' from 'netcheck.exporter'`.

- [ ] **Step 3: Add the placeholder helper to `src/netcheck/exporter.py`**

```python
_SECTION_TITLES = {
    "connection": "## Connection & identity",
    "ip_geo": "## Connection & identity",
    "vpn_assessment": "## VPN / proxy assessment",
    "bgp": "## ASN & BGP intelligence",
    "reputation": "## Reputation",
    "latency": "## Latency",
    "path": "## Path",
    "speed": "## Speed",
}


def unavailable(report: dict[str, Any], section: str) -> str | None:
    module = _module(report, section)
    if module.get("status") in ("ok", "partial") and module.get("data") is not None:
        return None
    detail = "; ".join(f"{e.get('source')}: {e.get('message')}" for e in module.get("errors") or [])
    if not detail:
        detail = "no data was collected for this section"
    return f"_Not available — {module.get('status', 'skipped')}: {detail}._"
```

- [ ] **Step 4: Rewire every section renderer to open with the placeholder check**

Add the same two-line guard as the first statement of `_connection`, `_vpn`, `_bgp`, `_reputation`, `_latency`, `_path` and `_speed`, using each function's own section key and heading:

```python
def _bgp(report: dict) -> list[str]:
    note = unavailable(report, "bgp")
    if note:
        return [_SECTION_TITLES["bgp"], "", note, ""]
    # the rest of the Task 35 body follows here unchanged
```

`_connection` checks both of its inputs, because the section merges two modules:

```python
def _connection(report: dict) -> list[str]:
    note = unavailable(report, "connection") or unavailable(report, "ip_geo")
    if note:
        return [_SECTION_TITLES["connection"], "", note, ""]
    # the rest of the Task 35 body follows here unchanged
```

`_tldr`, `_problems` and `_diagnostics` need no guard: they read `interpretation` and the module envelopes, both of which exist even when every probe died.

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_exporter.py -q`
Expected: PASS, 46 tests.

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, ~250 tests, no failures.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/exporter.py tests/test_exporter.py
git commit -m "exporter: explicit placeholders so a failed section never reads as a healthy one"
```

---
## Phase 7 — Orchestration

### Task 37: `cli.py` — Typer app, flags and the phase pipeline

**Files:**
- Replace: `src/netcheck/cli.py` (the Task 1 stub is discarded entirely)
- Modify: `src/netcheck/probes/traceroute.py` (append the opt-in `--tcp-trace` tier)
- Test: `tests/test_traceroute_cascade.py` (append — the tcp-trace tier ordering only)

**Interfaces:**
- Consumes: everything built so far — `load_settings` (Task 5), `run_module`/`gather_modules`/`utc_now_iso` (Task 6), `detect_capabilities`/`collect_local_net`/`is_tunnel_iface` (Tasks 7–8), `gather_identity`/`dual_stack_mismatch` (Task 18), `collect_bgp` (Task 21), `refresh_netsets`/`query_dnsbl`/`fetch_internetdb`/`fetch_abuseipdb`/`normalize_internetdb`/`build_reputation` (Tasks 22–24), `ping_fanout` (Task 25), `traceroute` (Task 28), `collect_dns_leak` (Task 30), `run_speed_cascade`/`tier_*`/`measure_with_bufferbloat`/`NDT7_CONSENT_NOTICE` (Tasks 31–33), `gather_vpn_signals`/`assess_vpn`/`latency_findings`/`path_findings`/`speed_findings` (Tasks 14–16), `build_report`/`render_markdown`/`write_report` (Tasks 34–36).
- Produces:
  - `app: typer.Typer`, `main() -> None`
  - `Options` dataclass carrying the parsed flags
  - `parse_target(value: str) -> tuple[str, str]`
  - `async diagnose(settings: Settings, options: Options) -> tuple[dict, str, Path, Path]`
  - `tier_order(caps, tcp_trace: bool = False)` and `traceroute(..., tcp_trace: bool = False)` gain the opt-in tier

**Testing note:** this task is wiring, and the testing policy names Typer wiring as glue — there are no unit tests for the pipeline itself. Every piece it calls is already covered by Tasks 3–36, and the honest verification for the wiring is running it, which Step 6 does with an exact command and exact expectations. The one genuinely new *logic* here is the extra traceroute tier, which gets a real test in the probes' own test file.

- [ ] **Step 1: Write the failing test for the opt-in tcp-trace tier (append to `tests/test_traceroute_cascade.py`)**

```python
def test_tcp_trace_is_absent_unless_it_is_asked_for():
    assert "tcp_trace" not in tier_order(caps(icmp_dgram=True, traceroute_binary="/usr/bin/traceroute"))
    assert "tcp_trace" not in tier_order(caps(os_name="Windows", icmp_win_api=True))


def test_tcp_trace_leads_the_cascade_when_requested():
    order = tier_order(caps(mtr_binary="/usr/bin/mtr", icmp_dgram=True), tcp_trace=True)
    assert order[0] == "tcp_trace"
    assert order[1:] == ["mtr_json", "icmplib"]


def test_tcp_trace_can_be_the_only_tier():
    assert tier_order(caps(), tcp_trace=True) == ["tcp_trace"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_traceroute_cascade.py -q -k tcp_trace`
Expected: FAIL — `TypeError: tier_order() got an unexpected keyword argument 'tcp_trace'`.

- [ ] **Step 3: Add the tier to `src/netcheck/probes/traceroute.py`**

Change `tier_order` to accept the flag (the existing default keeps every Task 28 test passing):

```python
def tier_order(caps: Capabilities, tcp_trace: bool = False) -> list[str]:
    # An explicit --tcp-trace means the user already knows ICMP is being filtered,
    # so it leads rather than sits behind tiers that are about to fail.
    order: list[str] = ["tcp_trace"] if tcp_trace else []
    if caps.mtr_binary:
        order.append("mtr_json")
    if caps.icmp_win_api:
        order.append("icmp_win")
    elif caps.icmp_dgram or caps.icmp_raw:
        order.append("icmplib")
    if caps.traceroute_binary:
        order.append("system_traceroute")
    return order
```

Append the tier implementation and extend `traceroute`:

```python
async def _tier_tcp_trace(target: str, max_hops: int, timeout: float, port: int = 443) -> TraceResult:
    # scapy ships in the optional `tcptrace` extra and needs Npcap (Windows) or
    # root (Unix); an ImportError here just falls through to the next tier.
    from scapy.layers.inet import IP, TCP
    from scapy.sendrecv import sr

    def _probe() -> list[TraceHop]:
        answered, _unanswered = sr(
            IP(dst=target, ttl=(1, max_hops)) / TCP(dport=port, flags="S"),
            timeout=timeout,
            verbose=0,
        )
        hops = [
            finalize_hop(
                TraceHop(ttl=sent.ttl, ip=received.src, probes=[(received.time - sent.sent_time) * 1000.0])
            )
            for sent, received in answered
        ]
        return sorted(hops, key=lambda hop: hop.ttl)

    hops = await asyncio.to_thread(_probe)
    return TraceResult(
        target=target,
        backend="tcp_trace",
        hops=hops,
        cycles=1,
        completed=bool(hops) and hops[-1].ip == target,
        max_hops_reached=bool(hops) and hops[-1].ttl >= max_hops,
    )
```

In `traceroute`, add the builder entry and thread the flag through:

```python
async def traceroute(
    target: str,
    caps: Capabilities,
    max_hops: int,
    cycles: int,
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
    tcp_trace: bool = False,
) -> TraceResult:
    builders = {
        "tcp_trace": lambda: _tier_tcp_trace(target, max_hops, timeout),
        # the four Task 28 entries — mtr_json, icmp_win, icmplib, system_traceroute —
        # stay exactly as they were
    }
    tiers = [(name, builders[name]) for name in tier_order(caps, tcp_trace)]
    if semaphore is None:
        return await run_cascade(tiers)
    async with semaphore:
        return await run_cascade(tiers)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_traceroute_cascade.py -q`
Expected: PASS, 16 tests.

- [ ] **Step 5: Write `src/netcheck/cli.py`, replacing the stub**

```python
from __future__ import annotations

import asyncio
import os
import platform
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

import httpx
import typer
from rich.console import Console

from netcheck import __version__
from netcheck.compare import diff_reports, load_report, render_diff
from netcheck.config import Settings, load_settings
from netcheck.exporter import build_report, render_markdown, write_report
from netcheck.interpret import (
    assess_vpn,
    gather_vpn_signals,
    latency_findings,
    path_findings,
    speed_findings,
)
from netcheck.ip_geo import dual_stack_mismatch, gather_identity
from netcheck.models import Finding, IpGeo, LocalNet, ModuleResult, SpeedResult
from netcheck.netinfo import collect_local_net, detect_capabilities, is_tunnel_iface
from netcheck.orchestration import gather_modules, run_module, utc_now_iso
from netcheck.probes.dns_leak import collect_dns_leak
from netcheck.probes.latency import ping_fanout, tcp_connect_rtt
from netcheck.probes.traceroute import traceroute
from netcheck.speed import NDT7_CONSENT_NOTICE

app = typer.Typer(add_completion=False, help="Deep network diagnostics.")
console = Console()


@dataclass
class Options:
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


def parse_target(value: str) -> tuple[str, str]:
    text = value.strip()
    if text.upper().startswith("AS") and text[2:].isdigit():
        return "asn", text.upper()
    if text.isdigit():
        return "asn", f"AS{text}"
    if all(part.isdigit() for part in text.split(".")) and text.count(".") == 3:
        return "ip", text
    if ":" in text:
        return "ip", text
    return "domain", text


def _os_timezone() -> str | None:
    # The VPN timezone signal needs an IANA name; Windows has none, so the signal
    # simply stays unobserved there rather than being guessed at.
    if os.environ.get("TZ"):
        return os.environ["TZ"]
    localtime = Path("/etc/localtime")
    if localtime.is_symlink():
        return str(localtime.readlink()).split("zoneinfo/")[-1] or None
    try:
        return Path("/etc/timezone").read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return out
```

Then the collection helpers, each of which writes verbatim payloads into the shared `raw` sink:

```python
async def _identity(client: httpx.AsyncClient, settings: Settings, options: Options, raw: dict) -> dict:
    token = settings.ipinfo_token.get_secret_value() if settings.ipinfo_token else None
    lookup = options.target_value if options.target_kind in ("ip", "domain") else None
    merged, cf, flags, payloads = await gather_identity(
        client, settings.providers, ip=lookup, ipinfo_token=token
    )
    raw.update(payloads)
    v6 = None
    if options.target_kind is None:
        try:
            transport = httpx.AsyncHTTPTransport(local_address="::")
            async with httpx.AsyncClient(
                transport=transport, timeout=settings.timeouts.http_seconds
            ) as v6_client:
                v6_merged, _cf6, _flags6, _raw6 = await gather_identity(v6_client, settings.providers)
            v6 = v6_merged if v6_merged.ip else None
        except (httpx.HTTPError, OSError):
            v6 = None
    return {
        "egress_v4": merged,
        "egress_v6": v6,
        "cf_trace": cf,
        "dual_stack_note": dual_stack_mismatch(merged, v6),
        "_flags": flags,
    }


async def _bgp_section(client, settings: Settings, asn: str | None, raw: dict):
    if not asn:
        return ModuleResult(name="bgp", status="skipped", warnings=["no ASN was resolved for this target"])
    from netcheck.bgp import collect_bgp

    key = settings.peeringdb_api_key.get_secret_value() if settings.peeringdb_api_key else None
    intel, payloads = await collect_bgp(
        client, settings.providers, Path(settings.output.cache_dir), asn, peeringdb_key=key
    )
    raw.update(payloads)
    return ModuleResult(name="bgp", status="ok", data=intel)


async def _reputation_section(client, settings: Settings, options: Options, geo: IpGeo, raw: dict):
    from netcheck.reputation import (
        build_reputation,
        fetch_abuseipdb,
        fetch_internetdb,
        normalize_internetdb,
        query_dnsbl,
        refresh_netsets,
    )

    if not geo.ip:
        return ModuleResult(name="reputation", status="skipped", warnings=["no egress IP to check"])
    warnings: list[str] = []
    index = await refresh_netsets(client, settings.providers, Path(settings.output.cache_dir))
    payload = await fetch_internetdb(client, settings.providers, geo.ip)
    raw["internetdb"] = payload
    outcomes = None
    if options.dnsbl and geo.ip_version == 4:
        outcomes = await query_dnsbl(geo.ip, settings.dnsbl.zones, settings.timeouts.dns_seconds)
    score = reports = None
    if settings.abuseipdb_api_key:
        abuse = await fetch_abuseipdb(
            client, settings.providers, geo.ip, settings.abuseipdb_api_key.get_secret_value()
        )
        raw["abuseipdb"] = abuse
        data = abuse.get("data") or {}
        score, reports = data.get("abuseConfidenceScore"), data.get("totalReports")
    else:
        warnings.append("ABUSEIPDB_API_KEY not set — abuse score skipped")
    reputation = build_reputation(
        internetdb=normalize_internetdb(payload),
        firehol_hits=index.hits(geo.ip),
        dnsbl_outcomes=outcomes,
        ip_type=geo.ip_type,
        abuseipdb_score=score,
        abuseipdb_reports=reports,
    )
    return ModuleResult(
        name="reputation", status="partial" if warnings else "ok", data=reputation, warnings=warnings
    )


async def _traces(hosts, caps, settings: Settings, cycles: int, options: Options):
    semaphore = asyncio.Semaphore(settings.probing.trace_concurrency)
    return list(
        await asyncio.gather(
            *(
                traceroute(
                    host,
                    caps,
                    max_hops=settings.probing.max_hops,
                    cycles=cycles,
                    timeout=settings.timeouts.subprocess_seconds,
                    semaphore=semaphore,
                    tcp_trace=options.tcp_trace,
                )
                for _label, host in hosts
            )
        )
    )


async def _speed_section(client, settings: Settings, options: Options, idle_rtt_ms: float | None):
    import shutil

    from netcheck.speed import (
        measure_with_bufferbloat,
        run_speed_cascade,
        tier_cloudflare,
        tier_fastcom,
        tier_ndt7,
        tier_ookla,
    )

    cfg = settings.speedtest
    timeout = settings.timeouts.speedtest_seconds
    builders = {
        "ookla_bin": lambda: tier_ookla(
            shutil.which("speedtest") or "speedtest", options.speedtest_server, timeout
        ),
        "cloudflare": lambda: tier_cloudflare(client, cfg, timeout),
        "fastcom": lambda: tier_fastcom(client, cfg, timeout),
        "ndt7": lambda: tier_ndt7(client, cfg, timeout),
    }
    enabled = list(cfg.enabled_tiers) + (["ndt7"] if options.ndt7 else [])
    result = await run_speed_cascade([(name, builders[name]) for name in enabled if name in builders])
    if result.method == "none":
        return ModuleResult(name="speed", status="failed", data=result)

    async def _saturate_down() -> None:
        await client.get(
            f"{cfg.cloudflare_base_url}/__down", params={"bytes": cfg.download_sizes_bytes[-1]}, timeout=timeout
        )

    async def _saturate_up() -> None:
        await client.post(
            f"{cfg.cloudflare_base_url}/__up", content=b"\x00" * cfg.upload_sizes_bytes[-1], timeout=timeout
        )

    async def _probe() -> float | None:
        return await tcp_connect_rtt("1.1.1.1", timeout=settings.probing.ping_timeout_seconds)

    result = await measure_with_bufferbloat(
        result,
        idle_rtt_ms=idle_rtt_ms if result.idle_rtt_ms is None else result.idle_rtt_ms,
        bands=settings.thresholds.bufferbloat_ms,
        run_download=_saturate_down,
        run_upload=_saturate_up,
        probe=_probe,
        interval=cfg.bufferbloat_probe_interval_seconds,
    )
    return ModuleResult(name="speed", status="ok", data=result)
```

Then the pipeline itself, in the spec §12 phase order:

```python
async def diagnose(settings: Settings, options: Options) -> tuple[dict, str, Path, Path]:
    started_at = utc_now_iso()
    caps = detect_capabilities()
    timeouts = settings.timeouts
    modules: dict[str, ModuleResult] = {}
    raw: dict[str, Any] = {}

    async with httpx.AsyncClient(
        timeout=timeouts.http_seconds,
        follow_redirects=True,
        http2=True,
        headers={"User-Agent": f"netcheck/{__version__}"},
    ) as client:
        # Phase 1 — local facts and identity. Blocking: everything below needs the ASN.
        modules["connection"] = await run_module(
            "connection", asyncio.to_thread(collect_local_net), timeout=timeouts.module_seconds
        )
        local = modules["connection"].data or LocalNet()
        modules["ip_geo"] = await run_module(
            "ip_geo", _identity(client, settings, options, raw), timeout=timeouts.module_seconds
        )
        bundle = modules["ip_geo"].data or {}
        flags = bundle.pop("_flags", {}) if isinstance(bundle, dict) else {}
        geo = bundle.get("egress_v4") or IpGeo()
        if bundle.get("dual_stack_note"):
            modules["ip_geo"].warnings.append(bundle["dual_stack_note"])
        asn = geo.asn if options.target_kind != "asn" else options.target_value

        # Phase 2 — bgp || reputation || dns_leak
        bgp_result, rep_result, dns_result = await gather_modules(
            run_module("bgp", _bgp_section(client, settings, asn, raw), timeout=timeouts.module_seconds),
            run_module(
                "reputation", _reputation_section(client, settings, options, geo, raw), timeout=timeouts.module_seconds
            ),
            run_module(
                "dns_leak",
                collect_dns_leak(local, asn, settings.providers.cymru_origin_zone, timeouts.dns_seconds),
                timeout=timeouts.module_seconds,
            ),
        )
        modules["bgp"], modules["reputation"] = bgp_result, rep_result
        signals = gather_vpn_signals(
            local=local,
            geo=geo,
            cf=bundle.get("cf_trace"),
            dns_leak=dns_result.data,
            pdb_info_type=getattr(bgp_result.data, "pdb_info_type", None),
            os_timezone=_os_timezone(),
            provider_flags=flags,
        )
        modules["vpn_assessment"] = ModuleResult(
            name="vpn_assessment",
            status="ok" if dns_result.status == "ok" else "partial",
            data=assess_vpn(
                signals,
                settings.thresholds.vpn_confidence,
                tunnel_iface=local.iface_name if is_tunnel_iface(local.iface_name or "") else None,
                dns_leak=dns_result.data,
            ),
            errors=dns_result.errors,
            started_at=dns_result.started_at,
            duration_ms=dns_result.duration_ms,
        )

        # Phase 3 — latency || traceroute, both bounded
        hosts = [(h.label, h.host) for h in settings.probing.reference_hosts]
        if not options.quick:
            hosts += [(h.label, h.host) for h in settings.probing.service_hosts]
        if options.extra_host:
            hosts.append(("target-host", options.extra_host))
        if options.target_kind in ("ip", "domain"):
            hosts.append(("target", options.target_value))
        count = settings.probing.quick_ping_count if options.quick else settings.probing.ping_count
        cycles = settings.probing.quick_mtr_cycles if options.quick else settings.probing.mtr_cycles
        modules["latency"], modules["path"] = await gather_modules(
            run_module(
                "latency",
                ping_fanout(
                    hosts,
                    caps,
                    count,
                    settings.probing.ping_interval_seconds,
                    settings.probing.ping_timeout_seconds,
                ),
                timeout=timeouts.subprocess_seconds,
            ),
            run_module("path", _traces(hosts, caps, settings, cycles, options), timeout=timeouts.subprocess_seconds),
        )

        # Phase 4 — speed, exclusive: nothing else is in flight at this point.
        pings = modules["latency"].data or []
        idle_rtt = min((p.avg_ms for p in pings if p.avg_ms is not None), default=None)
        skip_speed = options.quick or (options.mode == "target" and not options.speedtest_server)
        if skip_speed:
            modules["speed"] = ModuleResult(
                name="speed",
                status="skipped",
                warnings=["speedtest skipped: --quick" if options.quick else "speedtest skipped in target mode"],
            )
        else:
            modules["speed"] = await run_module(
                "speed", _speed_section(client, settings, options, idle_rtt), timeout=timeouts.speedtest_seconds
            )

    # Phase 5 — interpret
    speed = modules["speed"].data or SpeedResult()
    findings = _dedupe(
        latency_findings(pings, settings.thresholds)
        + [f for trace in (modules["path"].data or []) for f in path_findings(trace)]
        + speed_findings(speed, settings.thresholds.bufferbloat_ms)
    )

    # Phase 6 — export
    meta = {
        "run_id": uuid.uuid4().hex[:12],
        "started_at": started_at,
        "finished_at": utc_now_iso(),
        "mode": options.mode,
        "target": options.target_value,
        "flags": {
            "quick": options.quick,
            "full": options.full,
            "dnsbl": options.dnsbl,
            "ndt7": options.ndt7,
            "tcp_trace": options.tcp_trace,
        },
        "host_os": f"{platform.system()} {platform.release()}",
        "capabilities": caps,
    }
    report = build_report(meta, modules, findings, raw)
    markdown = render_markdown(report, emoji=settings.output.emoji)
    json_path, md_path = write_report(report, markdown, Path(settings.output.logs_dir))
    return report, markdown, json_path, md_path
```

And the Typer command:

```python
@app.command()
def run(
    full: bool = typer.Option(False, "--full", help="Full run: speedtest and full MTR cycles."),
    quick: bool = typer.Option(False, "--quick", help="Express run: reference hosts only, no speedtest."),
    target: Optional[str] = typer.Option(None, "--target", help="Investigate AS<n>, an IP or a domain."),
    target_host: Optional[str] = typer.Option(None, "--target-host", help="Extra host for ping/traceroute."),
    speedtest_server: Optional[str] = typer.Option(None, "--speedtest-server", help="Pin the speedtest server."),
    watch: bool = typer.Option(False, "--watch", help="Continuous monitoring with a live dashboard."),
    compare: Optional[Tuple[Path, Path]] = typer.Option(None, "--compare", help="Diff two saved JSON reports."),
    dnsbl: bool = typer.Option(False, "--dnsbl", help="Also query classic DNSBL zones."),
    ndt7: bool = typer.Option(False, "--ndt7", help="Add the M-Lab NDT7 speedtest tier (publishes your IP)."),
    tcp_trace: bool = typer.Option(False, "--tcp-trace", help="Add a scapy TCP-SYN traceroute tier."),
) -> None:
    settings = load_settings()
    if compare:
        before, after = load_report(compare[0]), load_report(compare[1])
        console.print(render_diff(diff_reports(before, after), emoji=settings.output.emoji))
        raise typer.Exit(0)

    kind, value = parse_target(target) if target else (None, None)
    options = Options(
        mode="target" if target else "auto",
        target_kind=kind,
        target_value=value,
        quick=quick and not full,
        full=full,
        extra_host=target_host,
        speedtest_server=speedtest_server,
        dnsbl=dnsbl,
        ndt7=ndt7,
        tcp_trace=tcp_trace,
    )
    if ndt7:
        console.print(f"[yellow]{NDT7_CONSENT_NOTICE}[/yellow]")
        if sys.stdin.isatty() and not typer.confirm("Continue with NDT7?", default=False):
            options.ndt7 = False
    if tcp_trace:
        console.print(
            "[yellow]--tcp-trace needs Npcap (Windows) or root (Unix) and the `tcptrace` extra; "
            "if it cannot run, the cascade falls through to the normal tiers.[/yellow]"
        )
    if watch:
        from netcheck.watch import run_watch

        asyncio.run(run_watch(settings, options))
        raise typer.Exit(0)

    console.print(f"netcheck {__version__} · {options.mode} mode · {platform.system()}")
    report, _markdown, json_path, md_path = asyncio.run(diagnose(settings, options))
    interpretation = report["interpretation"]
    console.print(
        f"Verdict: [bold]{interpretation['overall_status']}[/bold] "
        f"({interpretation['overall_score']}/100) — {interpretation['summary_text']}"
    )
    console.print(f"Report written to {md_path}\n                 {json_path}")


def main() -> None:
    app()
```

`cli.py` holds no business logic: every line is flag parsing, phase sequencing, or printing. The speedtest phase is exclusive by construction — it runs after every `gather_modules` above it has already returned (spec §12).

Spec §12 also asks for per-host semaphores on the rate-limited providers (ip-api 45/min, PeeringDB 20/min). This pipeline does not need them and deliberately does not add them: ip-api is contacted at most twice per run (once per address family) and PeeringDB responses are served from the disk cache built in Task 20, so neither can approach its limit from a single run. That reasoning stops holding the moment any of these providers is called inside a loop — if a later change does that (a per-hop ASN lookup, a per-adapter enrichment), add the semaphore at that call site rather than here.

- [ ] **Step 6: Manual smoke test — the express run**

Run:

```bash
uv run netcheck --quick
```

Expected on the console, in this order:

1. `netcheck 0.1.0 · auto mode · <Windows|Linux|Darwin>`
2. A `Verdict: ok (100/100) — No problems found on this connection.` line (score and text vary with the link; any of `ok`/`warn`/`crit` is a valid outcome — what must be true is that the line prints and names a score).
3. Two paths under `logs/`, an `.md` and a `.json` with the same stem.

No traceback, no elevation prompt, and the whole run finishes in roughly 10–20 seconds.

Then check the artifacts:

```bash
uv run python - <<'PY'
import json, pathlib
newest = max(pathlib.Path("logs").glob("report_*.json"), key=lambda p: p.stat().st_mtime)
report = json.loads(newest.read_text(encoding="utf-8"))
print(newest.name)
print("keys:", sorted(report))
print("statuses:", {k: report[k]["status"] for k in ("connection","ip_geo","vpn_assessment","bgp","reputation","latency","path","speed")})
print("egress:", (report["ip_geo"]["data"] or {}).get("egress_v4", {}).get("ip"))
print("asn:", (report["ip_geo"]["data"] or {}).get("egress_v4", {}).get("asn"))
print("findings:", [f["id"] for f in report["interpretation"]["findings"]])
print("errors:", [(e["module"], e["kind"]) for e in report["errors"]])
PY
```

Expected: the filename is `report_AS<n>_<stamp>.json` (or `report_unknown_…` only if identity truly failed); `keys` contains all of `schema_version, meta, connection, ip_geo, vpn_assessment, bgp, reputation, latency, path, speed, interpretation, errors, raw`; `speed` is `skipped` (that is what `--quick` means); `latency` and `connection` are `ok` or `partial`; `egress`/`asn` are populated. Individual provider errors in `errors` are acceptable and expected — a rate-limited provider must not have aborted anything.

Open the Markdown next to it and confirm all ten `##` sections are present and no section is silently empty.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/cli.py src/netcheck/probes/traceroute.py tests/test_traceroute_cascade.py
git commit -m "cli: typer app, phase pipeline and opt-in tcp-syn trace tier"
```

---

### Task 38: `compare.py` — diff two saved reports

**Files:**
- Create: `src/netcheck/compare.py`
- Create: `tests/fixtures/reports/before.json`, `tests/fixtures/reports/after.json`
- Test: `tests/test_compare.py`

**Interfaces:**
- Consumes: the JSON report shape from Task 34; `badge` (Task 35).
- Produces:
  - `Change` dataclass: `label: str, before: Any, after: Any, delta: float | None`
  - `ReportDiff` dataclass: `identity, latency, speed: list[Change]`, `new_findings, resolved_findings: list[dict]`
  - `load_report(path: Path) -> dict`
  - `identity_changes(before: dict, after: dict) -> list[Change]`
  - `latency_changes(before: dict, after: dict) -> list[Change]`
  - `speed_changes(before: dict, after: dict) -> list[Change]`
  - `finding_changes(before: dict, after: dict) -> tuple[list[dict], list[dict]]`
  - `diff_reports(before: dict, after: dict) -> ReportDiff`
  - `render_diff(diff: ReportDiff, emoji: bool = True) -> str`

Read-only: `--compare` never probes anything (spec §15).

- [ ] **Step 1: Create the two fixture reports**

`tests/fixtures/reports/before.json` — a healthy run with no VPN:

```json
{
  "schema_version": 1,
  "meta": { "run_id": "aaaa1111", "started_at": "2026-08-08T19:12:00Z", "mode": "auto", "target": null },
  "connection": { "name": "connection", "status": "ok", "data": { "iface_name": "Wi-Fi 2" }, "errors": [], "warnings": [], "duration_ms": 40 },
  "ip_geo": {
    "name": "ip_geo",
    "status": "ok",
    "data": {
      "egress_v4": {
        "ip": "203.0.113.44",
        "asn": "AS64500",
        "as_name": "Example Telecom",
        "org": "Example Telecom BV",
        "country_code": "NL",
        "ip_type": "residential"
      },
      "egress_v6": null,
      "cf_trace": null,
      "dual_stack_note": null
    },
    "errors": [],
    "warnings": [],
    "duration_ms": 900
  },
  "vpn_assessment": {
    "name": "vpn_assessment",
    "status": "ok",
    "data": { "verdict": "none", "confidence": 0.1, "signals": [], "tunnel_iface": null, "dns_leak": null },
    "errors": [],
    "warnings": [],
    "duration_ms": 300
  },
  "bgp": { "name": "bgp", "status": "ok", "data": { "asn": "AS64500", "holder": "Example Telecom BV" }, "errors": [], "warnings": [], "duration_ms": 1200 },
  "reputation": { "name": "reputation", "status": "ok", "data": { "captcha_risk": "low", "firehol_hits": [] }, "errors": [], "warnings": [], "duration_ms": 800 },
  "latency": {
    "name": "latency",
    "status": "ok",
    "data": [
      { "label": "cloudflare-dns", "host": "1.1.1.1", "method": "icmp_win", "avg_ms": 12.4, "jitter_ms": 1.9, "loss_pct": 0.0 },
      { "label": "google-dns", "host": "8.8.8.8", "method": "icmp_win", "avg_ms": 14.0, "jitter_ms": 2.0, "loss_pct": 0.0 }
    ],
    "errors": [],
    "warnings": [],
    "duration_ms": 5200
  },
  "path": { "name": "path", "status": "ok", "data": [], "errors": [], "warnings": [], "duration_ms": 4000 },
  "speed": {
    "name": "speed",
    "status": "ok",
    "data": {
      "method": "cloudflare",
      "download_mbps": 284.3,
      "upload_mbps": 41.7,
      "bufferbloat_down_ms": 12.0,
      "bufferbloat_grade": "B"
    },
    "errors": [],
    "warnings": [],
    "duration_ms": 30000
  },
  "interpretation": {
    "overall_status": "ok",
    "overall_score": 100,
    "summary_text": "No problems found on this connection.",
    "findings": []
  },
  "errors": [],
  "raw": {}
}
```

`tests/fixtures/reports/after.json` — the same link with a VPN up, worse latency, slower speed and one new finding:

```json
{
  "schema_version": 1,
  "meta": { "run_id": "bbbb2222", "started_at": "2026-08-08T21:40:00Z", "mode": "auto", "target": null },
  "connection": { "name": "connection", "status": "ok", "data": { "iface_name": "wg0" }, "errors": [], "warnings": [], "duration_ms": 41 },
  "ip_geo": {
    "name": "ip_geo",
    "status": "ok",
    "data": {
      "egress_v4": {
        "ip": "198.51.100.7",
        "asn": "AS64777",
        "as_name": "Example Hosting",
        "org": "Example Hosting BV",
        "country_code": "DE",
        "ip_type": "hosting"
      },
      "egress_v6": null,
      "cf_trace": null,
      "dual_stack_note": null
    },
    "errors": [],
    "warnings": [],
    "duration_ms": 950
  },
  "vpn_assessment": {
    "name": "vpn_assessment",
    "status": "ok",
    "data": { "verdict": "confirmed", "confidence": 0.75, "signals": [], "tunnel_iface": "wg0", "dns_leak": null },
    "errors": [],
    "warnings": [],
    "duration_ms": 310
  },
  "bgp": { "name": "bgp", "status": "ok", "data": { "asn": "AS64777", "holder": "Example Hosting BV" }, "errors": [], "warnings": [], "duration_ms": 1300 },
  "reputation": { "name": "reputation", "status": "ok", "data": { "captcha_risk": "medium", "firehol_hits": [] }, "errors": [], "warnings": [], "duration_ms": 820 },
  "latency": {
    "name": "latency",
    "status": "ok",
    "data": [
      { "label": "cloudflare-dns", "host": "1.1.1.1", "method": "icmp_win", "avg_ms": 46.9, "jitter_ms": 1.9, "loss_pct": 0.0 },
      { "label": "quad9-dns", "host": "9.9.9.9", "method": "icmp_win", "avg_ms": 48.0, "jitter_ms": 3.0, "loss_pct": 1.0 }
    ],
    "errors": [],
    "warnings": [],
    "duration_ms": 5400
  },
  "path": { "name": "path", "status": "ok", "data": [], "errors": [], "warnings": [], "duration_ms": 4100 },
  "speed": {
    "name": "speed",
    "status": "ok",
    "data": {
      "method": "cloudflare",
      "download_mbps": 96.1,
      "upload_mbps": 38.0,
      "bufferbloat_down_ms": 74.0,
      "bufferbloat_grade": "D"
    },
    "errors": [],
    "warnings": [],
    "duration_ms": 31000
  },
  "interpretation": {
    "overall_status": "crit",
    "overall_score": 75,
    "summary_text": "Bufferbloat under load (downstream): grade D",
    "findings": [
      {
        "id": "speed.bufferbloat_down",
        "severity": "crit",
        "title": "Bufferbloat under load (downstream): grade D",
        "detail": "Latency rose by 74.0 ms while saturating the downstream direction.",
        "metric": "bufferbloat_down_ms",
        "value": "D",
        "threshold": 60.0,
        "advice": "Enabling SQM/fq_codel on the router is the standard fix."
      }
    ]
  },
  "errors": [],
  "raw": {}
}
```

- [ ] **Step 2: Write the failing test**

`tests/test_compare.py`:

```python
from __future__ import annotations

import pytest

from netcheck.compare import (
    Change,
    diff_reports,
    finding_changes,
    identity_changes,
    latency_changes,
    load_report,
    render_diff,
    speed_changes,
)


@pytest.fixture()
def before(fixtures_dir):
    return load_report(fixtures_dir / "reports" / "before.json")


@pytest.fixture()
def after(fixtures_dir):
    return load_report(fixtures_dir / "reports" / "after.json")


def by_label(changes: list[Change]) -> dict[str, Change]:
    return {c.label: c for c in changes}


def test_load_report_reads_a_saved_report(before):
    assert before["schema_version"] == 1
    assert before["meta"]["run_id"] == "aaaa1111"


def test_identity_reports_the_egress_and_asn_change(before, after):
    changes = by_label(identity_changes(before, after))
    assert changes["Egress IP"].before == "203.0.113.44"
    assert changes["Egress IP"].after == "198.51.100.7"
    assert changes["ASN"].before == "AS64500"
    assert changes["ASN"].after == "AS64777"
    assert changes["Country"].after == "DE"
    assert changes["Address type"].after == "hosting"


def test_identity_reports_the_vpn_verdict_and_confidence_delta(before, after):
    changes = by_label(identity_changes(before, after))
    assert changes["VPN verdict"].before == "none"
    assert changes["VPN verdict"].after == "confirmed"
    assert changes["VPN confidence"].delta == pytest.approx(0.65)


def test_identity_of_a_report_against_itself_is_empty(before):
    assert identity_changes(before, before) == []


def test_latency_deltas_are_signed_per_host_and_metric(before, after):
    changes = by_label(latency_changes(before, after))
    assert changes["cloudflare-dns avg_ms"].delta == pytest.approx(34.5)
    assert changes["cloudflare-dns avg_ms"].before == 12.4
    assert "cloudflare-dns jitter_ms" not in changes


def test_a_host_present_in_only_one_report_is_still_reported(before, after):
    changes = by_label(latency_changes(before, after))
    assert changes["google-dns avg_ms"].after is None
    assert changes["quad9-dns avg_ms"].before is None
    assert changes["quad9-dns avg_ms"].delta is None


def test_latency_of_a_report_against_itself_is_empty(before):
    assert latency_changes(before, before) == []


def test_speed_deltas_cover_throughput_and_the_bufferbloat_grade(before, after):
    changes = by_label(speed_changes(before, after))
    assert changes["Download Mbps"].delta == pytest.approx(-188.2)
    assert changes["Upload Mbps"].delta == pytest.approx(-3.7)
    assert changes["Bufferbloat grade"].before == "B"
    assert changes["Bufferbloat grade"].after == "D"
    assert "Speedtest method" not in changes


def test_findings_are_split_into_new_and_resolved(before, after):
    new, resolved = finding_changes(before, after)
    assert [f["id"] for f in new] == ["speed.bufferbloat_down"]
    assert resolved == []
    new, resolved = finding_changes(after, before)
    assert new == []
    assert [f["id"] for f in resolved] == ["speed.bufferbloat_down"]


def test_diff_reports_assembles_every_part(before, after):
    diff = diff_reports(before, after)
    assert diff.identity
    assert diff.latency
    assert diff.speed
    assert len(diff.new_findings) == 1
    assert diff.resolved_findings == []


def test_render_diff_shows_before_and_after_values(before, after):
    text = render_diff(diff_reports(before, after))
    assert text.startswith("# netcheck compare")
    assert "203.0.113.44" in text
    assert "198.51.100.7" in text
    assert "-188.2" in text
    assert "Bufferbloat under load" in text


def test_render_diff_of_two_identical_reports_says_so(before):
    text = render_diff(diff_reports(before, before))
    assert text.count("No change.") == 3
    assert "No findings appeared or cleared." in text


def test_render_diff_honours_the_emoji_setting(before, after):
    assert "🔴" in render_diff(diff_reports(before, after), emoji=True)
    assert "[crit]" in render_diff(diff_reports(before, after), emoji=False)
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_compare.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.compare'`.

- [ ] **Step 4: Implement `src/netcheck/compare.py`**

```python
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcheck.exporter import badge


@dataclass
class Change:
    label: str
    before: Any = None
    after: Any = None
    delta: float | None = None


@dataclass
class ReportDiff:
    identity: list[Change] = field(default_factory=list)
    latency: list[Change] = field(default_factory=list)
    speed: list[Change] = field(default_factory=list)
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)


def load_report(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _data(report: dict, section: str) -> Any:
    return (report.get(section) or {}).get("data")


def _geo(report: dict) -> dict:
    bundle = _data(report, "ip_geo") or {}
    return (bundle.get("egress_v4") or {}) if isinstance(bundle, dict) else {}


def _delta(before: Any, after: Any) -> float | None:
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        return round(float(after) - float(before), 3)
    return None


def identity_changes(before: dict, after: dict) -> list[Change]:
    a, b = _geo(before), _geo(after)
    vpn_a = _data(before, "vpn_assessment") or {}
    vpn_b = _data(after, "vpn_assessment") or {}
    pairs = [
        ("Egress IP", a.get("ip"), b.get("ip")),
        ("ASN", a.get("asn"), b.get("asn")),
        ("Organisation", a.get("as_name") or a.get("org"), b.get("as_name") or b.get("org")),
        ("Country", a.get("country_code"), b.get("country_code")),
        ("Address type", a.get("ip_type"), b.get("ip_type")),
        ("VPN verdict", vpn_a.get("verdict"), vpn_b.get("verdict")),
        ("VPN confidence", vpn_a.get("confidence"), vpn_b.get("confidence")),
    ]
    return [Change(label, x, y, _delta(x, y)) for label, x, y in pairs if x != y]


def latency_changes(before: dict, after: dict) -> list[Change]:
    a = {p.get("label"): p for p in _data(before, "latency") or []}
    b = {p.get("label"): p for p in _data(after, "latency") or []}
    changes: list[Change] = []
    for label in sorted(set(a) | set(b)):
        pa, pb = a.get(label) or {}, b.get(label) or {}
        for metric in ("avg_ms", "jitter_ms", "loss_pct"):
            x, y = pa.get(metric), pb.get(metric)
            if x != y:
                changes.append(Change(f"{label} {metric}", x, y, _delta(x, y)))
    return changes


def speed_changes(before: dict, after: dict) -> list[Change]:
    a, b = _data(before, "speed") or {}, _data(after, "speed") or {}
    fields = (
        ("Speedtest method", "method"),
        ("Download Mbps", "download_mbps"),
        ("Upload Mbps", "upload_mbps"),
        ("Bufferbloat down ms", "bufferbloat_down_ms"),
        ("Bufferbloat up ms", "bufferbloat_up_ms"),
        ("Bufferbloat grade", "bufferbloat_grade"),
    )
    return [
        Change(label, a.get(key), b.get(key), _delta(a.get(key), b.get(key)))
        for label, key in fields
        if a.get(key) != b.get(key)
    ]


def finding_changes(before: dict, after: dict) -> tuple[list[dict], list[dict]]:
    a = {f.get("id"): f for f in (before.get("interpretation") or {}).get("findings") or []}
    b = {f.get("id"): f for f in (after.get("interpretation") or {}).get("findings") or []}
    return [b[i] for i in b if i not in a], [a[i] for i in a if i not in b]


def diff_reports(before: dict, after: dict) -> ReportDiff:
    new, resolved = finding_changes(before, after)
    return ReportDiff(
        identity=identity_changes(before, after),
        latency=latency_changes(before, after),
        speed=speed_changes(before, after),
        new_findings=new,
        resolved_findings=resolved,
    )


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    return f"{value:g}" if isinstance(value, (int, float)) else str(value)


def _block(title: str, changes: list[Change]) -> list[str]:
    if not changes:
        return [f"### {title}", "", "No change.", ""]
    return (
        [f"### {title}", "", "| Field | Before | After | Δ |", "|---|---|---|---|"]
        + [f"| {c.label} | {_fmt(c.before)} | {_fmt(c.after)} | {_fmt(c.delta)} |" for c in changes]
        + [""]
    )


def render_diff(diff: ReportDiff, emoji: bool = True) -> str:
    lines = ["# netcheck compare", ""]
    lines += _block("Identity", diff.identity)
    lines += _block("Latency", diff.latency)
    lines += _block("Speed", diff.speed)
    lines += ["### Findings", ""]
    if not diff.new_findings and not diff.resolved_findings:
        lines += ["No findings appeared or cleared.", ""]
    else:
        lines += [
            f"- new: {badge(f.get('severity', 'info'), emoji)} {f.get('title', '')}" for f in diff.new_findings
        ]
        lines += [f"- resolved: {badge('ok', emoji)} {f.get('title', '')}" for f in diff.resolved_findings]
        lines += [""]
    return "\n".join(lines).rstrip() + "\n"
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_compare.py -q`
Expected: PASS, 13 tests.

- [ ] **Step 6: Verify `--compare` end to end against the fixtures**

Run: `uv run netcheck --compare tests/fixtures/reports/before.json tests/fixtures/reports/after.json`
Expected: the compare document printed to the terminal with an Identity table showing `203.0.113.44 → 198.51.100.7`, a Latency table with signed deltas, a Speed table with `-188.2`, and one new finding. No network access happens.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/compare.py tests/test_compare.py tests/fixtures/reports
git commit -m "compare: diff identity, latency, speed and findings between two reports"
```

---
## Phase 8 — Watch

### Task 39: `watch.py` — the monitoring loop and its one time-series artifact

**Files:**
- Create: `src/netcheck/watch.py`
- Test: `tests/test_watch.py`

**Interfaces:**
- Consumes: `PingResult`, `SpeedResult`, `to_jsonable` (Tasks 3–4); `sanitize_name`, `compact_timestamp`, `dump_json`, `atomic_write`, `sparkline` (Tasks 34–35); `ping_fanout` (Task 25); `detect_capabilities` (Task 7); `utc_now_iso`/`run_module` (Task 6).
- Produces:
  - `WATCH_SCHEMA_VERSION: int`
  - `is_speedtest_cycle(cycle: int, every_n: int) -> bool`
  - `next_delay(cycle_started: float, now: float, interval: float) -> float`
  - `summarize_cycle(cycle: int, at: str, pings: list[PingResult], speed: SpeedResult | None) -> dict`
  - `WatchSession` dataclass with `add`, `to_report`, `filename`, `history(label) -> list[float | None]`
  - `write_session(session: WatchSession, logs_dir: Path) -> Path`
  - `render_dashboard(session: WatchSession)` — Rich renderable, glue
  - `async run_watch(settings: Settings, options) -> Path` — glue

**Testing note:** most of this module is deliberately untested, and the testing policy names it by name: a real `asyncio.sleep` loop and a live Rich rendering surface cannot be meaningfully unit tested — a test of either would be a test of the mock. What *is* pure, and what this task tests properly, is the part that has actual logic and actual off-by-one risk: which cycle is a full-speedtest cycle, how long to sleep so the interval does not drift, how a cycle collapses into a summary row, and the accumulation of those rows into the single session artifact.

Spec §15 is explicit that a `--watch` session produces **one** time-series file, not one report per tick — `write_session` is called once, when the loop ends.

- [ ] **Step 1: Write the failing test**

`tests/test_watch.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

import pytest

from netcheck.models import PingResult, SpeedResult
from netcheck.watch import (
    WATCH_SCHEMA_VERSION,
    WatchSession,
    is_speedtest_cycle,
    next_delay,
    summarize_cycle,
    write_session,
)


def ping(label: str, avg: float | None, loss: float = 0.0) -> PingResult:
    return PingResult(
        label=label,
        host="1.1.1.1",
        resolved_ip="1.1.1.1",
        method="icmp_win",
        sent=5,
        received=5 if avg is not None else 0,
        loss_pct=loss,
        avg_ms=avg,
        jitter_ms=1.5,
    )


def test_the_first_cycle_measures_speed_so_the_session_has_a_baseline():
    assert is_speedtest_cycle(1, every_n=10) is True


def test_speed_is_measured_once_every_n_cycles():
    assert [c for c in range(1, 25) if is_speedtest_cycle(c, every_n=10)] == [1, 11, 21]


def test_an_interval_of_one_measures_speed_every_cycle():
    assert all(is_speedtest_cycle(c, every_n=1) for c in range(1, 6))


def test_a_non_positive_interval_disables_the_speedtest_entirely():
    assert [c for c in range(1, 10) if is_speedtest_cycle(c, every_n=0)] == []
    assert is_speedtest_cycle(3, every_n=-5) is False


def test_cycle_numbers_below_one_are_never_speedtest_cycles():
    assert is_speedtest_cycle(0, every_n=10) is False


def test_next_delay_subtracts_the_time_the_cycle_already_took():
    assert next_delay(cycle_started=100.0, now=104.0, interval=60.0) == pytest.approx(56.0)


def test_a_cycle_that_overran_its_interval_does_not_sleep_negatively():
    assert next_delay(cycle_started=100.0, now=400.0, interval=60.0) == 0.0


def test_summarize_cycle_flattens_the_hosts_and_omits_speed_when_it_did_not_run():
    summary = summarize_cycle(3, "2026-08-08T19:15:00Z", [ping("cloudflare-dns", 12.4)], None)
    assert summary["cycle"] == 3
    assert summary["at"] == "2026-08-08T19:15:00Z"
    assert summary["hosts"]["cloudflare-dns"]["avg_ms"] == 12.4
    assert summary["hosts"]["cloudflare-dns"]["loss_pct"] == 0.0
    assert summary["speed"] is None


def test_summarize_cycle_keeps_the_speed_figures_when_it_did_run():
    speed = SpeedResult(method="cloudflare", download_mbps=284.3, upload_mbps=41.7, bufferbloat_grade="B")
    summary = summarize_cycle(1, "2026-08-08T19:12:00Z", [ping("cloudflare-dns", 12.4)], speed)
    assert summary["speed"]["download_mbps"] == 284.3
    assert summary["speed"]["bufferbloat_grade"] == "B"


def test_summarize_cycle_records_a_dead_host_without_inventing_a_number():
    summary = summarize_cycle(2, "2026-08-08T19:13:00Z", [ping("google-dns", None, loss=100.0)], None)
    assert summary["hosts"]["google-dns"]["avg_ms"] is None
    assert summary["hosts"]["google-dns"]["loss_pct"] == 100.0


def test_session_history_returns_the_series_for_one_host_with_gaps_preserved():
    session = WatchSession(started_at="2026-08-08T19:12:00Z", asn="AS64500")
    session.add(summarize_cycle(1, "t1", [ping("cloudflare-dns", 12.0)], None))
    session.add(summarize_cycle(2, "t2", [ping("cloudflare-dns", None, loss=100.0)], None))
    session.add(summarize_cycle(3, "t3", [ping("cloudflare-dns", 14.0)], None))
    assert session.history("cloudflare-dns") == [12.0, None, 14.0]
    assert session.history("absent-host") == [None, None, None]


def test_session_filename_marks_it_as_a_watch_artifact():
    session = WatchSession(started_at="2026-08-08T19:12:00Z", asn="AS64500")
    assert session.filename() == "watch_AS64500_20260808T191200Z.json"
    assert WatchSession(started_at="2026-08-08T19:12:00Z").filename().startswith("watch_unknown_")


def test_a_session_writes_exactly_one_artifact_holding_every_cycle(tmp_path: Path):
    session = WatchSession(
        started_at="2026-08-08T19:12:00Z", asn="AS64500", interval_seconds=60, speedtest_every_n_cycles=10
    )
    for cycle in range(1, 4):
        session.add(summarize_cycle(cycle, f"t{cycle}", [ping("cloudflare-dns", 12.0 + cycle)], None))
    path = write_session(session, tmp_path)
    assert list(tmp_path.iterdir()) == [path]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == WATCH_SCHEMA_VERSION
    assert payload["kind"] == "watch"
    assert payload["meta"]["interval_seconds"] == 60
    assert payload["meta"]["speedtest_every_n_cycles"] == 10
    assert [c["cycle"] for c in payload["cycles"]] == [1, 2, 3]


def test_an_empty_session_still_writes_a_well_formed_artifact(tmp_path: Path):
    path = write_session(WatchSession(started_at="2026-08-08T19:12:00Z"), tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["cycles"] == []
    assert payload["meta"]["finished_at"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_watch.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netcheck.watch'`.

- [ ] **Step 3: Implement the pure part of `src/netcheck/watch.py`**

```python
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcheck.exporter import atomic_write, compact_timestamp, dump_json, sanitize_name
from netcheck.models import PingResult, SpeedResult, to_jsonable
from netcheck.orchestration import utc_now_iso

WATCH_SCHEMA_VERSION = 1


def is_speedtest_cycle(cycle: int, every_n: int) -> bool:
    # Cycle 1 measures speed so the session opens with a baseline to compare against.
    if every_n <= 0 or cycle < 1:
        return False
    return (cycle - 1) % every_n == 0


def next_delay(cycle_started: float, now: float, interval: float) -> float:
    # Subtracting the work already done keeps the cycle cadence from drifting
    # further behind on every tick.
    return max(0.0, interval - (now - cycle_started))


def summarize_cycle(
    cycle: int,
    at: str,
    pings: list[PingResult],
    speed: SpeedResult | None,
) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "at": at,
        "hosts": {
            p.label: {
                "host": p.host,
                "method": p.method,
                "avg_ms": p.avg_ms,
                "jitter_ms": p.jitter_ms,
                "loss_pct": p.loss_pct,
            }
            for p in pings
        },
        "speed": None
        if speed is None
        else {
            "method": speed.method,
            "download_mbps": speed.download_mbps,
            "upload_mbps": speed.upload_mbps,
            "bufferbloat_grade": speed.bufferbloat_grade,
        },
    }


@dataclass
class WatchSession:
    started_at: str
    asn: str | None = None
    interval_seconds: int = 60
    speedtest_every_n_cycles: int = 10
    cycles: list[dict] = field(default_factory=list)

    def add(self, summary: dict) -> None:
        self.cycles.append(summary)

    def history(self, label: str) -> list[float | None]:
        return [(cycle["hosts"].get(label) or {}).get("avg_ms") for cycle in self.cycles]

    def labels(self) -> list[str]:
        seen: list[str] = []
        for cycle in self.cycles:
            for label in cycle["hosts"]:
                if label not in seen:
                    seen.append(label)
        return seen

    def filename(self) -> str:
        return f"watch_{sanitize_name(self.asn)}_{compact_timestamp(self.started_at)}.json"

    def to_report(self) -> dict[str, Any]:
        return {
            "schema_version": WATCH_SCHEMA_VERSION,
            "kind": "watch",
            "meta": {
                "started_at": self.started_at,
                "finished_at": utc_now_iso(),
                "asn": self.asn,
                "interval_seconds": self.interval_seconds,
                "speedtest_every_n_cycles": self.speedtest_every_n_cycles,
                "cycle_count": len(self.cycles),
            },
            "cycles": to_jsonable(self.cycles),
        }


def write_session(session: WatchSession, logs_dir: Path) -> Path:
    return atomic_write(Path(logs_dir) / session.filename(), dump_json(session.to_report()))
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_watch.py -q`
Expected: PASS, 14 tests.

- [ ] **Step 5: Append the loop and dashboard glue to `src/netcheck/watch.py`**

```python
import asyncio
import time

import httpx
from rich.console import Console
from rich.live import Live
from rich.table import Table

from netcheck import __version__
from netcheck.config import Settings
from netcheck.exporter import sparkline
from netcheck.ip_geo import gather_identity
from netcheck.netinfo import detect_capabilities
from netcheck.orchestration import run_module
from netcheck.probes.latency import ping_fanout


def render_dashboard(session: WatchSession) -> Table:
    table = Table(title=f"netcheck --watch · {session.asn or 'unknown ASN'} · cycle {len(session.cycles)}")
    for column in ("Host", "Avg ms", "Jitter", "Loss", "Trend"):
        table.add_column(column)
    latest = session.cycles[-1]["hosts"] if session.cycles else {}
    for label in session.labels():
        row = latest.get(label) or {}
        table.add_row(
            label,
            "—" if row.get("avg_ms") is None else f"{row['avg_ms']:g}",
            "—" if row.get("jitter_ms") is None else f"{row['jitter_ms']:g}",
            f"{row.get('loss_pct', 0)}%",
            sparkline(session.history(label)[-40:]),
        )
    speed = next((c["speed"] for c in reversed(session.cycles) if c["speed"]), None)
    if speed:
        table.caption = (
            f"last speedtest: {speed['download_mbps']} / {speed['upload_mbps']} Mbps "
            f"via {speed['method']} · bufferbloat {speed['bufferbloat_grade']}"
        )
    return table


async def run_watch(settings: Settings, options) -> Path:
    # Imported here, not at module import time: cli imports watch lazily for --watch,
    # and a module-level import back into cli would close the cycle.
    from netcheck.cli import _speed_section

    caps = detect_capabilities()
    session = WatchSession(
        started_at=utc_now_iso(),
        interval_seconds=settings.watch.interval_seconds,
        speedtest_every_n_cycles=settings.watch.speedtest_every_n_cycles,
    )
    hosts = [(h.label, h.host) for h in settings.probing.reference_hosts]
    if options.extra_host:
        hosts.append(("target-host", options.extra_host))
    console = Console()
    console.print(f"netcheck {__version__} · watching every {session.interval_seconds}s · Ctrl-C to stop")

    async with httpx.AsyncClient(
        timeout=settings.timeouts.http_seconds,
        follow_redirects=True,
        headers={"User-Agent": f"netcheck/{__version__}"},
    ) as client:
        try:
            geo, _cf, _flags, _raw = await gather_identity(client, settings.providers)
            session.asn = geo.asn
        except (httpx.HTTPError, OSError):
            session.asn = None

        cycle = 1
        try:
            with Live(render_dashboard(session), console=console, refresh_per_second=settings.watch.dashboard_refresh_hz) as live:
                while True:
                    began = time.perf_counter()
                    pings = await ping_fanout(
                        hosts,
                        caps,
                        settings.probing.quick_ping_count,
                        settings.probing.ping_interval_seconds,
                        settings.probing.ping_timeout_seconds,
                    )
                    speed = None
                    if is_speedtest_cycle(cycle, session.speedtest_every_n_cycles) and not options.quick:
                        result = await run_module(
                            "speed",
                            _speed_section(client, settings, options, None),
                            timeout=settings.timeouts.speedtest_seconds,
                        )
                        speed = result.data if result.status == "ok" else None
                    session.add(summarize_cycle(cycle, utc_now_iso(), pings, speed))
                    live.update(render_dashboard(session))
                    await asyncio.sleep(next_delay(began, time.perf_counter(), session.interval_seconds))
                    cycle += 1
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass

    path = write_session(session, Path(settings.output.logs_dir))
    console.print(f"Watch session written to {path}")
    return path
```

One artifact per session, written on the way out — a `--watch` run left going overnight leaves a single time-series file behind, not several hundred reports (spec §15).

- [ ] **Step 6: Manual smoke test of the loop**

Run, and interrupt with Ctrl-C after roughly three cycles:

```bash
uv run netcheck --watch --quick
```

Expected: a live Rich table that redraws in place (not scrolling) with one row per reference host, an `Avg ms` figure and a trend sparkline that grows a glyph per cycle. Ctrl-C exits cleanly with no traceback and prints one `Watch session written to logs/watch_<ASN>_<stamp>.json` line. Confirm the artifact:

```bash
uv run python - <<'PY'
import json, pathlib
newest = max(pathlib.Path("logs").glob("watch_*.json"), key=lambda p: p.stat().st_mtime)
payload = json.loads(newest.read_text(encoding="utf-8"))
print(newest.name, payload["kind"], payload["meta"]["cycle_count"])
print([c["cycle"] for c in payload["cycles"]])
PY
```

Expected: `kind` is `watch`, `cycle_count` matches the number of cycles observed, and `logs/` gained exactly **one** new file for the whole session.

- [ ] **Step 7: Commit**

```bash
git add src/netcheck/watch.py tests/test_watch.py
git commit -m "watch: cycle scheduling, live dashboard and one time-series artifact per session"
```

---
## Phase 9 — Integration and project hygiene

### Task 40: End-to-end smoke test across all three modes

**Files:**
- Modify: none (verification only; any defect found is fixed in the module that owns it, with a regression test added to that module's test file)

**Interfaces:**
- Consumes: the whole assembled tool.
- Produces: confidence that the three real invocation modes work on a live network, and a written record of any degradation this machine cannot avoid.

This task has no unit tests by design: everything below is the live behaviour that the testing policy deliberately leaves untested. It is the only place the real network is exercised end to end, so it is written as explicit steps with explicit expectations rather than as prose.

- [ ] **Step 1: Confirm the suite is green before touching the network**

```bash
uv run pytest -q
```

Expected: all tests pass, roughly 280–300 of them, zero failures and zero collection errors. Do not continue to the live checks with a red suite — a live failure would be impossible to attribute.

- [ ] **Step 2: Express run — `--quick` in auto mode**

```bash
uv run netcheck --quick
```

Expected: finishes in roughly 10–20 seconds, no traceback, no elevation prompt, and a final pair of paths under `logs/`.

Open the Markdown report and verify by eye:

- The header names the mode (`auto`), both timestamps and a verdict line with a score out of 100.
- All ten `##` sections are present: TL;DR, Connection & identity, VPN / proxy assessment, ASN & BGP intelligence, Reputation, Latency, Path, Speed, Problems & recommendations, Run diagnostics.
- **Connection & identity** shows your real egress IPv4 and an `AS…` number that matches your ISP. IPv6 shows either a real address or `—`; both are correct outcomes.
- **VPN / proxy assessment** shows `none` on a plain connection, with a signals table where every row reads `no` except possibly `provider_mobile` on a phone hotspot.
- **Latency** has one row per reference host, a sparkline block underneath, and — if the machine fell back to TCP timing — the note that `tcp` loss counts failed connections rather than dropped packets.
- **Speed** is the placeholder `_Not available — skipped: …_`, because `--quick` skips it. This is the section that proves the spec §11 rule: a skipped speedtest must not look like a healthy one.
- **Run diagnostics** lists all eight modules with a status and a duration.

- [ ] **Step 3: Validate the `--quick` JSON against the spec §14 schema**

```bash
uv run python - <<'PY'
import json, pathlib
newest = max(pathlib.Path("logs").glob("report_*.json"), key=lambda p: p.stat().st_mtime)
report = json.loads(newest.read_text(encoding="utf-8"))

required = {
    "schema_version", "meta", "connection", "ip_geo", "vpn_assessment", "bgp",
    "reputation", "latency", "path", "speed", "interpretation", "errors", "raw",
}
missing = required - set(report)
print("file:", newest.name)
print("missing top-level keys:", missing or "none")
print("meta keys:", sorted(report["meta"]))
print("statuses:", {k: report[k]["status"] for k in ("connection","ip_geo","vpn_assessment","bgp","reputation","latency","path","speed")})
print("interpretation keys:", sorted(report["interpretation"]))
print("raw sources:", sorted(report["raw"]))
print("errors:", [(e["module"], e["source"], e["kind"]) for e in report["errors"]])
PY
```

Expected:

- `missing top-level keys: none`.
- `meta keys` contains `capabilities, finished_at, flags, host_os, mode, run_id, started_at, target`.
- `interpretation keys` is exactly `findings, overall_score, overall_status, summary_text`.
- `raw sources` is non-empty and contains provider keys such as `cf-trace`, `ip-api`, `ripestat-network-info` — this is the "100% of collected data" guarantee, so an empty `raw` on a working connection is a defect.
- `speed` status is `skipped`; every other module is `ok` or `partial`.
- Entries in `errors` are acceptable (a rate-limited provider is normal) as long as no module is `failed` on a healthy link.

Also confirm the file parses in strict mode — this is where the `inf`/`NaN` regression would surface:

```bash
uv run python -c "import json,pathlib; p=max(pathlib.Path('logs').glob('report_*.json'), key=lambda x: x.stat().st_mtime); json.loads(p.read_text(encoding='utf-8'), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f'non-finite literal: {c}'))); print('strict json ok')"
```

Expected: `strict json ok`. A `non-finite literal` error means something bypassed `to_jsonable` — fix it in `exporter.py` and add the case to `tests/test_exporter.py`.

- [ ] **Step 4: Full run — `--full` in auto mode**

**Caveat, read first:** this step actually saturates the link for 30–90 seconds. Run it only on a connection where that is acceptable, and not on a metered or shared connection. If the dev machine cannot run a real speedtest (metered link, corporate proxy, no bandwidth headroom), **skip this step and record why in the commit message for this task** — do not fake it and do not treat a skipped speedtest as a failure of the tool.

```bash
uv run netcheck --full
```

Expected: 60–120 seconds, no traceback. In the Markdown report:

- **Speed** is populated: a `Method` naming the tier that won (`ookla_bin` if the native binary is on PATH, otherwise `cloudflare`), non-zero download, an upload figure or `—` on a download-only tier, and a bufferbloat grade with the plain-language consequence sentence under the table.
- The **Cascade** sub-table lists every tier that was tried, with `no` and a reason for the ones that were not used — `binary not on PATH` is the expected reason on a machine without Ookla installed.
- **Path** now has a hop table per host inside a fenced block, with the ASCII bar column, and `<<` on the first sustained-loss hop if there is one.
- **Latency** rows use the full `ping_count`, so the sparklines are longer than in the `--quick` run.

- [ ] **Step 5: Target mode — a well-known ASN**

```bash
uv run netcheck --target AS15169
```

Expected: finishes in roughly 20–40 seconds. In the report:

- The header shows `target` mode and `AS15169`.
- **ASN & BGP intelligence** is the substantive section: holder resolves to Google, upstreams/peers/downstreams are populated, `Announced prefixes` counts are in the hundreds or thousands, `CAIDA ASRank` gives a rank and a customer-cone size, and the IXP table is long.
- **Speed** is `skipped` with the reason `speedtest skipped in target mode` — measuring the local line while asking about someone else's ASN would be misleading, which is exactly what spec §2 says.
- The filename is `report_AS15169_<stamp>.{md,json}`.

Then try the other two target forms and confirm they route correctly:

```bash
uv run netcheck --quick --target 8.8.8.8
uv run netcheck --quick --target one.one.one.one
```

Expected: both produce a report whose `ip_geo` describes the *target* address rather than your own egress, and whose latency fan-out includes a `target` row.

- [ ] **Step 6: Confirm nothing was left behind**

```bash
ls logs
git status --short
```

Expected: `logs/` holds only report pairs (and any watch artifact from Task 39) with no `.tmp` files left over — a stray `.tmp` means an atomic write was interrupted or the rename path is wrong. `git status --short` shows no changes at all: `logs/` and `.cache/` are gitignored, and this task modified no tracked file.

- [ ] **Step 7: Commit (only if a defect was fixed)**

If every step passed, there is nothing to commit — say so and move on. If a step exposed a defect, fix it in the owning module, add a regression test to that module's test file, and commit that:

```bash
git add src/netcheck tests
git commit -m "fix <module>: <what the smoke test caught>"
```

---

### Task 41: Documentation freshness pass

**Files:**
- Modify: `README.md`, `README.ru.md`, `ARCHITECTURE.md`, `ARCHITECTURE.ru.md` (only where they drifted)

**Interfaces:**
- Consumes: the final state of `src/netcheck/`, `pyproject.toml`, `config.yaml` and `cli.py`'s flag list.
- Produces: four documents that describe the tool that actually exists.

Task 2 wrote these four files before a single module existed. Nine phases later they are a prediction, not a description. Stale docs are a bug (project convention), and this is the task that closes the gap before the first public push.

- [ ] **Step 1: List what actually exists**

```bash
find src/netcheck -name "*.py" | sort
grep -o '\-\-[a-z-]*' src/netcheck/cli.py | sort -u
uv run python -c "import tomllib,pathlib; d=tomllib.loads(pathlib.Path('pyproject.toml').read_text(encoding='utf-8')); print(d['project']['dependencies']); print(d['project']['optional-dependencies']); print(d['dependency-groups'])"
uv run pytest -q --collect-only 2>/dev/null | tail -2
```

Keep the four outputs to hand: the module list, the real flag list, the real dependency list, and the real test count.

- [ ] **Step 2: Reconcile the module lists in both ARCHITECTURE files**

Compare the `find` output against the directory-layout block in `ARCHITECTURE.md` and `ARCHITECTURE.ru.md`. Check specifically:

- Every file under `src/netcheck/` appears in the block, and nothing in the block is missing from disk.
- One-line descriptions still match what the module does — in particular `exporter.py`, which by Task 35 knowingly exceeds the ~200-line guideline and should carry that note.
- The data-flow diagram's phase order matches `diagnose()` in `cli.py`: netinfo + ip_geo → bgp ∥ reputation ∥ dns_leak → latency ∥ traceroute → speed → interpret → exporter.
- The Storage section lists every path actually written: `logs/report_*.{md,json}`, `logs/watch_*.json` (added in Task 39 — check it is there, it did not exist when Task 2 wrote the section), `.cache/firehol/`, `.cache/pdb-*.json`.
- The Tests section's approximate count is within a handful of the real number from Step 1; the project convention wants it updated when the count moves by more than five.

- [ ] **Step 3: Reconcile the flag tables in both README files**

Compare the `grep` output against the "Handy things" table in `README.md` and `README.ru.md`. Every flag `cli.py` accepts must be documented, and every documented flag must exist. Pay attention to the ones whose behaviour was settled late:

- `--target` accepts `AS<n>`, a bare ASN number, an IP or a domain (Task 37's `parse_target`).
- `--ndt7` prints a consent notice and asks for confirmation on an interactive terminal — the README should say so, not just that it publishes data.
- `--tcp-trace` requires the `tcptrace` extra plus Npcap or root, and falls through to the normal cascade when it cannot run.
- `--watch` writes one `watch_*.json` per session, not one report per tick.
- `--compare` is read-only and performs no probing.

- [ ] **Step 4: Reconcile the install and developer sections**

- The requirements list under Install matches the real dependency list from Step 1, including the two optional extras and their install command (`uv sync --extra tcptrace --extra ndt7`).
- The "For developers" code block's commands all still work as written — run each one.
- The sample console output at the top of both READMEs resembles what Task 40 Step 2 actually printed. It does not need to be a literal transcript, but it must not show a line format the tool never emits.

- [ ] **Step 5: Verify the bilingual pair stayed in sync**

```bash
head -3 README.md README.ru.md ARCHITECTURE.md ARCHITECTURE.ru.md
grep -c '^#' README.md README.ru.md
grep -c '^#' ARCHITECTURE.md ARCHITECTURE.ru.md
```

Expected: the cross-links on line 3 of each file are intact, and each pair has the same heading count — a divergence means an edit landed in one language only. Fix the lagging file; both are full standalone translations, never a stub pointing at the other.

- [ ] **Step 6: Commit**

```bash
git add README.md README.ru.md ARCHITECTURE.md ARCHITECTURE.ru.md
git commit -m "docs: sync readme and architecture with the final module and flag set"
```

---

### Task 42: `TASKS.md`

**Files:**
- Create: `TASKS.md`

**Interfaces:**
- Consumes: the finished state of the repository.
- Produces: the outstanding-work record for whoever picks this up next.

`netcheck` has no personal parent workspace and no `docs/` convention for working notes, so `TASKS.md` goes in the project root (placement rule 3). It tracks what is *left*, not what happened — `git log` already tells that story, and duplicating it here is what makes these files rot.

- [ ] **Step 1: Write `TASKS.md`**

```markdown
# TASKS

## Done

- Scaffold: uv packaging, `config.yaml`, `.env.example`, package skeleton, bilingual README and ARCHITECTURE
- `models.py` — ModuleResult/ProbeError/Finding/Signal envelopes and every domain shape
- `config.py` — pydantic-settings loader, env > .env > config.yaml > default
- `orchestration.py` — `run_module` envelope and exception classification
- `netinfo.py` — capability detection, backend choice, local interface/gateway/MTU/resolver facts
- `stats.py` — RTT loss, mdev and jitter
- `traceparse.py` — Linux, Windows (incl. cp866) and BSD parsers plus the OS dispatcher
- `interpret.py` — threshold bands, latency/path/speed findings, VPN scoring, bufferbloat grading
- `ip_geo.py` — six-provider normalizers, field-wise merge, dual-stack comparison
- `bgp.py` — RIPEstat, CAIDA ASRank, Team Cymru, disk-cached PeeringDB
- `reputation.py` — FireHOL netset index, DNSBL `127.255.255.x` decoding, InternetDB, captcha risk
- `probes/latency.py` — ping summarization and unprivileged backend fan-out
- `probes/icmp_win.py` — `IcmpSendEcho2` engine and reply decoding
- `probes/traceroute.py` — mtr → icmp_win → icmplib → system-binary cascade, plus opt-in TCP-SYN tier
- `probes/dns_leak.py` — per-adapter resolver enumeration, ASN mismatch and ECS detection
- `speed.py` — throughput math, `cfL4` parsing, four-tier cascade, bufferbloat under load
- `exporter.py` — strict JSON, atomic writes, Markdown rendering, failed-section placeholders
- `cli.py` — Typer app, every flag, the spec §12 phase pipeline
- `compare.py` — diff two saved reports
- `watch.py` — monitoring loop with one time-series artifact per session
- End-to-end smoke test across `--quick`, `--full` and `--target` modes
- Documentation freshness pass against the final module and flag set

## In Progress

- Nothing

## Next

- Finalize the license: MIT vs Polyform Noncommercial (spec §18). Polyform is the recommendation, because Shodan InternetDB and the free Spamhaus mirrors are non-commercial-use-only and MIT would let a downstream commercial fork violate those terms. If MIT wins, add the caveat to both READMEs. Replace the placeholder `LICENSE` before the first public push.
- Consider publishing to PyPI: decide on the distribution name, add a release workflow, and confirm the `tcptrace`/`ndt7` extras install cleanly from a wheel rather than from the repo.
- Revisit the opt-in extras' UX. `--ndt7` currently prints its consent notice and prompts on every interactive run, and `--tcp-trace` prints its privilege warning unconditionally. Decide whether consent should be remembered (a flag in `config.yaml`, or a marker in `.cache/`) so a repeat user is not re-prompted, and what the right behaviour is when stdin is not a TTY.

## Blocked

- Nothing
```

- [ ] **Step 2: Verify the file reads as outstanding work, not as a changelog**

Re-read the `Next` section on its own. Each entry must state a decision that is still open or a step not yet taken; if an entry only describes something already finished, it belongs in `Done` or nowhere. `Done` is intentionally a one-line-per-module inventory rather than a commit list — it answers "what exists", which `git log --oneline` does not answer at a glance.

- [ ] **Step 3: Commit**

```bash
git add TASKS.md
git commit -m "tasks: outstanding work after the initial implementation"
```

---
