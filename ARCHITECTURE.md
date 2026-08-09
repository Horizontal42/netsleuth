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
    traceroute.py Cascade: mtr --json -> icmp_win -> icmplib -> system binary text, plus the opt-in tcp_trace tier.
    icmp_win.py   ctypes IcmpSendEcho2 / Icmp6SendEcho2 engine (Windows only).
    dns_leak.py   Per-adapter resolver enumeration, echo probes, ECS detection.
```

**File-size exceptions.** The ~200-line guideline (Global Constraints) held for most modules, but these grew past it during implementation and were kept as single files rather than split, because each one is a single cohesive responsibility that splitting would only scatter across more files with a thinner reason to draw the line anywhere in particular:

- `exporter.py` (~475 lines) — JSON and Markdown are two renderers of the same report shape; keeping them together is what guarantees they can never drift on which sections exist.
- `cli.py` (~465 lines) — the Typer app, every flag, and the full `diagnose()` phase pipeline; splitting flag parsing from what the flags toggle would just add an import hop.
- `models.py` (~330 lines) — every shared dataclass plus `to_jsonable()`; this is deliberately the one place that defines the report's vocabulary.
- `interpret.py` (~320 lines) — threshold bands, the latency/path/speed finding generators, VPN scoring and bufferbloat grading all reason over the same `Finding[]` shape.
- `bgp.py` (~305 lines) — four independent providers (RIPEstat, CAIDA ASRank, Team Cymru, PeeringDB) plus the disk cache they share.
- `ip_geo.py` (~280 lines) — six independent provider normalizers plus the field-wise merge that reconciles them.
- `netinfo.py`, `speed.py` (~260 lines each) — OS-specific capability probing and the four-tier speedtest cascade both fan out into several backends that don't split cleanly by single responsibility.
- `reputation.py` (~250 lines) — FireHOL netsets, Shodan InternetDB and DNSBL decoding are three unrelated reputation sources sharing one result shape.
- `probes/traceroute.py` (~225 lines) — the four-tier cascade plus the opt-in `tcp_trace` tier.

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

- `./logs/report_<ASN>_<YYYYMMDDTHHMMSSZ>.{md,json}` — one pair per run. `<ASN>` is the target's subject in target mode (an ASN, IP or domain) and the local egress ASN in auto mode. Compact ISO timestamps because Windows forbids `:` in filenames. Falls back to `report_unknown_…` when the ASN lookup fails entirely. Written temp-file-plus-`os.replace()`, always atomic. Gitignored: reports contain the external IP, city, coordinates and ISP name.
- `./logs/watch_<ASN>_<YYYYMMDDTHHMMSSZ>.json` — one time-series artifact per `--watch` session, not one report per tick.
- `./.cache/firehol/*.netset` — downloaded blocklists, refreshed per `providers.firehol_refresh_hours`.
- `./.cache/pdb-net-<asn>.json`, `./.cache/pdb-netixlan-<net_id>.json` — PeeringDB responses, valid for `providers.peeringdb_cache_hours`.
- `./config.yaml` — all non-secret settings. `./.env` — the three optional API keys and nothing else.

## Configuration

`config.py` builds a pydantic-settings `Settings` object whose sources are ordered **init > environment > `.env` > `config.yaml` > field default**. The three API keys are `SecretStr | None = None` at the top level: a diagnostics tool must run with zero configuration, so a missing key downgrades the enrichment that needs it to `skipped` with a warning and never fails the run.

## Tests

`uv run pytest -q`. Roughly 385 tests covering the parsers, normalizers, verdict engine, DNSBL decoding, throughput math, ping statistics, serialization and the report diff. Glue is deliberately untested: live HTTP, real ICMP, Typer wiring, `psutil`/`ctypes` calls and the `--watch` timing loop. Traceroute fixtures live in `tests/fixtures/traceroute/{windows,linux,darwin}/` and include a cp866-encoded Russian Windows sample, because that encoding is exactly what breaks naive parsers.
