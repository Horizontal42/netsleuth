# netcheck — design spec

Date: 2026-08-08
Status: approved for planning

## 1. Purpose

A cross-platform (Windows / Linux / macOS) Python 3.10+ CLI for deep network diagnostics: current-connection analysis (ISP/VPN/ASN identity, latency, path, bandwidth) and target-mode lookups (a given ASN/IP/domain). Produces a human-readable Markdown report and a complete machine-readable JSON dump per run. Personal/open-source tool, not commercial — this gates which free-tier APIs are usable (see §7).

## 2. Modes and flags

- **Auto mode (default):** diagnoses the device's active connection.
- **Target mode:** `--target AS<n>` or `--target <ip|domain>` — investigates a specific ASN/host instead of the local connection. Speedtest is skipped in target mode by default (measures the local line, not the target) unless explicitly requested.
- `--full` / `--quick` — full run (speedtest + MTR, ~60–120s) vs express (~10s: reference-host pings only, `mtr_cycles=1`, no speedtest).
- `--target-host <ip|domain>` — extra host added to ping/traceroute fan-out.
- `--speedtest-server <id|url>` — explicit speedtest server override.
- `--watch` — continuous monitoring: periodic re-run (lightweight probes; full speedtest only at a configurable interval), live Rich dashboard in-terminal. For catching intermittent issues (VPN drops in the evening, etc).
- `--compare <report_a.json> <report_b.json>` — diffs two prior JSON reports from `./logs/`, prints what changed (before/after a VPN switch, before/after an ISP call).
- `--dnsbl` — opt-in classic DNSBL reputation check (off by default, see §6).
- `--ndt7` — opt-in M-Lab NDT7 bandwidth tier in the speedtest cascade, with an explicit one-time consent notice (every NDT7 measurement is published as open CC0 data including the client IP — see §5).
- `--tcp-trace` — opt-in scapy-based TCP-SYN traceroute for probing through ICMP-filtering middleboxes (needs Npcap on Windows / root elsewhere). Not part of the default path.

## 3. Module layout

Public surface named in the brief (`cli.py`, `ip_geo.py`, `bgp.py`, `prober.py`, `speed.py`, `exporter.py`) plus supporting modules, split to respect the project convention of ~200 lines/file and one responsibility per module:

```
netcheck/
  pyproject.toml            # uv-based, source of truth
  uv.lock
  requirements.txt          # generated, for non-uv users
  config.yaml
  .env.example
  .gitignore                 # must include logs/, .claude/, .venv/
  README.md
  ARCHITECTURE.md
  src/netcheck/
    __init__.py  __main__.py
    cli.py                   # Typer app, flag parsing, phase orchestration, Rich progress — no business logic
    config.py                # pydantic-settings, YamlConfigSettingsSource, env > .env > yaml > default
    models.py                # ModuleResult[T], ProbeError, Finding, Signal — shared shapes
    netinfo.py               # local iface/gateway/MTU/DNS servers, 3-way OS branch
    ip_geo.py                # multi-provider identity/geo/IP-type + VPN signal gathering
    bgp.py                   # RIPEstat + CAIDA ASRank + Team Cymru + PeeringDB
    reputation.py            # FireHOL cached netsets + Shodan InternetDB + optional DNSBL/AbuseIPDB
    probes/
      __init__.py
      latency.py             # ping/jitter fan-out (icmplib / IcmpSendEcho2 / TCP-timing / cfL4)
      traceroute.py           # mtr → per-OS unprivileged ICMP → system-binary cascade
      icmp_win.py             # ctypes IcmpSendEcho2/Icmp6SendEcho2 engine (Windows only)
      dns_leak.py              # per-adapter resolver enumeration + echo probes + ECS detection
    traceparse.py             # pure text→TraceHop parsers: Windows/Linux/macOS
    speed.py                  # cascading speedtest: Ookla bin → Cloudflare → fast.com → [--ndt7]
    interpret.py              # pure verdict engine: thresholds → Finding[], VPN confidence scoring
    exporter.py               # JSON + Markdown rendering, atomic writes to ./logs/
    compare.py                # --compare: diff two JSON reports
    watch.py                  # --watch: periodic re-run loop + live Rich dashboard
  tests/
    conftest.py
    test_traceparse.py  test_interpret.py  test_exporter.py
    test_ip_geo_normalize.py  test_speed_math.py  test_prober_stats.py
    test_dnsbl_decode.py  test_compare.py
    fixtures/traceroute/{windows,linux,darwin}/*.txt
    fixtures/api/*.json
  logs/                      # gitignored — reports contain external IP, city, coords
```

## 4. Core data shapes

```
ModuleResult[T]:  name, status(ok|partial|failed|skipped), data: T|None,
                  errors: list[ProbeError], warnings: list[str],
                  started_at, duration_ms
ProbeError:       source, kind(timeout|http_error|rate_limited|blocked|
                  parse_error|unavailable|no_privilege|not_applicable), message, retryable
Finding:          id, severity(ok|info|warn|crit), title, detail, metric, value, threshold, advice
Signal:           name, observed, weight: float, direction(vpn|clean), note

Capabilities:     os_name('Windows'|'Linux'|'Darwin'), is_elevated,
                  icmp_dgram, icmp_raw, icmp_win_api,
                  mtr_binary, traceroute_binary,
                  chosen_latency_backend, chosen_trace_backend, notes

LocalNet:         iface_name, local_ipv4, local_ipv6, iface_mtu,
                  default_gateway_v4/v6, dns_servers_per_adapter: dict[str, list[str]],
                  is_dual_stack

IpGeo:            ip, ip_version, reverse_dns, asn, as_name, org,
                  country, country_code, city, lat, lon, timezone,
                  ip_type(residential|mobile|hosting|business|unknown), sources: dict[str,str]

VpnAssessment:    verdict(none|likely|confirmed), confidence, signals: list[Signal],
                  tunnel_iface, dns_leak: DnsLeak|None

DnsLeak:          per_adapter: list[AdapterLeakResult], ecs_leaked: bool, note
AdapterLeakResult: adapter, configured_resolvers: list[str],
                  echoed_ip, echoed_asn, matches_egress_asn

BgpIntel:         asn, holder, registry, allocated_at,
                  upstreams, peers, downstreams,
                  announced_prefixes, prefix_count_v4/v6,
                  flaps: list[BgpEvent], stability(stable|unstable|unknown),
                  ixps: list[IxpPresence], pdb_info_type, pdb_traffic,
                  asrank, cone_asns, cone_prefixes            # from CAIDA ASRank

Reputation:       internetdb: InternetDbResult|None,
                  firehol_hits: list[str],                    # matched blocklist names
                  dnsbl_hits: list[DnsblHit] | None,           # only if --dnsbl
                  dnsbl_query_blocked: bool,                    # true if resolver returned 127.255.255.254
                  abuseipdb_score, abuseipdb_reports,           # only if keyed
                  captcha_risk(low|medium|high), rationale

PingResult:       label, host, resolved_ip, method(icmp_win|icmp_dgram|icmp_raw|tcp|cfL4),
                  sent, received, loss_pct, min_ms, avg_ms, max_ms, mdev_ms, jitter_ms, samples

TraceHop:         ttl, ip, reverse_dns, asn, as_name, probes: list[float|None],
                  loss_pct, min_ms, avg_ms, max_ms, jitter_ms, annotations

TraceResult:      target, resolved_ip, backend(mtr_json|icmp_win|icmplib|system_traceroute|tcp_trace|none),
                  hops: list[TraceHop], cycles, completed, max_hops_reached

SpeedResult:      method(ookla_bin|cloudflare|fastcom|ndt7|none), tier_attempts: list[TierAttempt],
                  download_mbps, upload_mbps|None, server,
                  idle_rtt_ms, loaded_rtt_down_ms, loaded_rtt_up_ms,
                  bufferbloat_down_ms, bufferbloat_up_ms, bufferbloat_grade,
                  cfL4_stats: CfL4Stats|None, netflix_oca_onnet: bool|None
```

## 5. Speedtest cascade

1. **Ookla native binary** if on PATH (`speedtest --format=json --accept-license --accept-gdpr`). `speedtest-cli` (pip) is archived/unmaintained since 2021 — not used.
2. **Cloudflare** — raw httpx against `speed.cloudflare.com/__down`/`__up`, ramping transfer sizes, 90th-percentile throughput; harvest `cdn-cgi/trace` (`warp=`/`gateway=`/`rbi=` — also feeds VPN signals, §6) and the `Server-Timing: cfL4` header (kernel TCP RTT/loss/retransmit — used as an ICMP-free latency fallback everywhere, not just here).
3. **fast.com (Netflix)** — `api.fast.com/netflix/speedtest/v2` public token, download-only, download from returned OCA target URLs; the OCA hostname reveals on-net-vs-off-net Netflix appliance placement, a real ISP-peering-quality signal RIPEstat/PeeringDB can't provide directly.
4. **`--ndt7` (opt-in)** — M-Lab NDT7 over WebSocket via `locate.measurementlab.net`. Best TCP-level fidelity (BBR/retransmit detail). Requires one-time consent notice: results are published publicly as CC0 open data including the client IP. Not in the default cascade.

Bufferbloat measured inside `speed.py`: a concurrent latency probe loop during saturation, compared to the idle RTT baseline from `probes/latency.py`, graded A–F, download and upload reported separately.

Fails gracefully — cascade exhaustion yields `status=failed` for `speed`, never an exception; rest of the report unaffected.

## 6. VPN / IP-type detection

**Provider chain (parallel, merged by field):**
- `cdn-cgi/trace` (Cloudflare) — egress IP, colo, country, `warp`/`gateway`/`rbi` flags
- `ip-api.com` — geo/ASN + `mobile`/`proxy`/`hosting` booleans (HTTP-only free tier)
- `freeipapi.com` — HTTPS keyless equivalent, used in parallel so an ip-api block/rate-limit doesn't blank the classification
- `ipinfo.io` — opportunistic enrichment if a token is configured (keyless free tier 429s in practice; `privacy` field is paid-only)
- `ipwho.is` — geo/ASN backup
- RIPEstat `network-info` — authoritative prefix/ASN

Both IPv4 and IPv6 egress resolved and compared — providers have been observed to disagree (dual-stack egress can differ per path); mismatch is reported, not silently resolved.

**VPN confidence signals** (scored in `interpret.py`, gathered elsewhere):
private-gateway-vs-egress mismatch; tunnel interface present (`tun*`/`tap*`/`wg*`/`utun*`/`ppp*`, Windows `WireGuard Tunnel`/`TAP-Windows`); MTU anomaly (WireGuard ~1420, IPsec ~1400); `hosting`/`proxy`/`mobile` flags from the provider chain; Cloudflare `warp=on`; PeeringDB `info_type` indicating NSP/hosting rather than eyeball ISP; DNS-resolver-ASN ≠ egress-ASN (§ DNS leak below); OS timezone vs geo country mismatch.

**DNS leak test:** enumerate DNS servers per network adapter (not just "the system resolver" — catches the case where the VPN's tunnel adapter is clean but a Wi-Fi adapter still holds the ISP resolver). For each configured resolver, send echo probes to `o-o.myaddr.l.google.com` (TXT) and `whoami.ds.akahelp.net` (TXT — also surfaces EDNS Client Subnet leakage, a separate finding from ASN mismatch), map the echoed IP to an ASN via Team Cymru DNS, compare against egress ASN. Reported per-adapter. Report language is explicit that this detects OS-level resolver leaks only — a browser using DoH bypasses it.

## 7. BGP / ASN intelligence

- **RIPEstat** (`stat.ripe.net`, keyless) — `as-overview`, `asn-neighbours` (upstreams/peers/downstreams), `announced-prefixes`, `routing-status`, `bgp-updates` (flap history), `whois`. Verified global (no ARIN/APNIC-region gap). `routing-history`/similar bulk endpoints **must** be called with bounded `max_rows`/timeframe — unbounded calls on large ISPs return 10MB+ payloads.
- **CAIDA ASRank** (`api.asrank.caida.org`, keyless) — rank, customer-cone size (ASNs/prefixes/addresses), degree (customer/peer/provider) — the "how big is this network" metric RIPEstat doesn't have.
- **Team Cymru** (`<ip>.origin.asn.cymru.com` TXT, keyless DNS) — IP→ASN/prefix/RIR/alloc-date fallback for when HTTPS is unavailable; also used to resolve DNS-leak echo results (§6).
- **PeeringDB** (`www.peeringdb.com/api`, keyless REST) — IXP presence, `info_type`/`info_traffic`/`policy_general`. Anonymous limits are tight (20 req/min, large responses throttled to 1/hour) — results cached to disk, never re-fetched within a run.
- BGPView.io is defunct (shut down 2025-11-26) — not used. bgp.he.net is HTML-only — not scraped. bgp.tools has no REST API (whois:43 + static table dumps only, mandatory identifying User-Agent, HTML scraping bans) — not used in v1, candidate for a later optional enrichment.

## 8. Reputation

**Default (keyless, no per-query disclosure to a third party of "which IP am I checking"):**
- **FireHOL / community IP blocklists** — cached netset download (~2–5MB, refreshed periodically per config), local prefix-trie lookup. No runtime query, no rate limit, no privacy exposure.
- **Shodan InternetDB** (`internetdb.shodan.io`, keyless) — open ports/hostnames/tags on the egress IP. More actionable for a home user than a mail-blocklist hit (exposed router, forgotten port-forward). Free for non-commercial use, matching netcheck's own status (§ project status).

**Opt-in:**
- `--dnsbl` — classic Spamhaus ZEN / SpamCop / Barracuda / DroneBL zone queries. **Must** decode Spamhaus's `127.255.255.x` error range correctly: `.254` means "you queried via a public resolver" (hits a large share of real users on 1.1.1.1/8.8.8.8) and `.255` means rate-limited — neither is a listing, and a naive "any 127.x.x.x = listed" implementation produces false-positive red flags for most users. Both are surfaced as "DNSBL result unavailable" rather than a finding.
- AbuseIPDB / IPQualityScore — only when a key is configured in `.env`.

## 9. Traceroute / MTR

Cascade, no privilege ever required for the default path:

1. `mtr --json`/`mtr --report --json` binary if present (best data: per-hop loss% and stddev for free).
2. **Windows:** ctypes engine (`icmp_win.py`) around `IcmpSendEcho2`/`Icmp6SendEcho2` (`Iphlpapi.dll`) — the same unprivileged API `tracert.exe` itself uses internally. No Administrator, no Npcap, stdlib-only (`ctypes`). Per-hop RTT, TTL-expired detection, proper timeout handling — strictly better data than parsing `tracert.exe`'s text output (3 fixed probes, localized headers, no loss%/jitter).
3. **Linux/macOS:** `icmplib` unprivileged mode (`SOCK_DGRAM` ICMP) — works out of the box on macOS, on Linux subject to `net.ipv4.ping_group_range` (true by default on most desktop distros, may need adjustment in containers); falls back to `icmplib` privileged (raw socket, needs root) when available.
4. Text-parsing the system binary (`tracert.exe` / GNU `traceroute` / BSD `traceroute`) as the last resort, via `traceparse.py` — three separate parsers, since Windows/Linux/macOS output formats genuinely differ (BSD emits multi-IP-per-hop lines and `!H`/`!N`/`!X` annotations Linux doesn't; Windows output is locale- and code-page-dependent — cp866 on Russian Windows, not UTF-8 — so parsing is by line *shape* (leading hop integer, RTT tokens, IP regex), never by matching header/footer text).
5. `--tcp-trace` (opt-in, not default): scapy TCP-SYN traceroute for getting past ICMP-filtering middleboxes. Needs Npcap (Windows) / root (Unix) — kept out of the default dependency set and default path entirely.

Latency probing (`probes/latency.py`) never parses `ping`'s own text output (would mean three more locale-dependent parsers for no benefit): uses `icmp_win`/`icmplib` when available, else TCP-connect timing to port 443, else the Cloudflare `cfL4` header. Every result is tagged with the method used — TCP "loss" (connection-failure rate) and ICMP loss are different metrics and must never be silently conflated in the report.

## 10. Capability detection

Attempt-based, never OS-assumption-based; cached once per run into `Capabilities`, included in JSON `meta`.

- Elevation: `ctypes.windll.shell32.IsUserAnAdmin()` (Windows) / `os.geteuid() == 0` (Linux, macOS).
- ICMP: try unprivileged `SOCK_DGRAM` ICMP → raw `SOCK_RAW` ICMP → (Windows) `IcmpSendEcho2` availability (always available, no privilege check needed) → none.
- Never require elevation for the default path — worst case degrades to TCP-connect timing + system-binary traceroute + `cfL4` header, and the report states the degradation once, plainly, with the one-line remedy.

## 11. Error handling

Single wrapper `async def run_module(name, coro, *, timeout) -> ModuleResult` — times the call, enforces a per-module timeout, catches `BaseException` except `CancelledError`, classifies into `ProbeError.kind`, always returns a well-formed envelope. `asyncio.gather(..., return_exceptions=True)` as a second net at the orchestration layer. Failure is a value, not control flow — no single API/probe failure aborts the run.

Four status levels: `ok` → `partial` (some sub-sources failed) → `failed` (nothing usable) → `skipped` (not applicable / missing optional key).

Both outputs surface every failure: JSON carries per-module `errors[]` plus a flattened top-level `errors[]` union; Markdown has a mandatory "Run diagnostics" section (module/status/duration/error table) plus inline placeholders in the body instead of silently omitting sections (a report missing its speed section must not be indistinguishable from a report where speed was fine).

`exporter.py` uses `json.dumps(..., allow_nan=False)`, coercing `inf`/`NaN` (possible from zero-duration timing math) to `null` before serialization — otherwise "strictly valid JSON" breaks on exactly the failure cases that matter most.

## 12. Concurrency model

Single shared `httpx.AsyncClient`; per-host semaphores for rate-limited APIs (ip-api 45/min, PeeringDB 20/min). Blocking calls (`speedtest` binary via subprocess is fine natively; `icmplib`/ctypes send/receive; `psutil` enumeration) via `asyncio.to_thread` where genuinely blocking. Subprocess traceroute via `asyncio.create_subprocess_exec` (native on all three OSes, no thread wrapper needed).

Two hard constraints:
1. **Measurement isolation** — speedtest never overlaps traceroute/ping/API calls (an exclusive phase lock); the one intentional exception is the bufferbloat probe, which overlaps saturation *by design* inside `speed.py`.
2. **Bounded traceroute fan-out** — parallel traceroutes to different targets share early hops and inflate each other's latency; bound concurrent traceroutes with a semaphore (2–3), never unbounded `gather`.

Phase order: `netinfo` + `ip_geo` provider chain (blocking — everything downstream needs the ASN) → `bgp` ∥ `reputation` ∥ `dns_leak` (parallel) → `latency` ∥ `traceroute` fan-out (parallel, bounded) → `speed` (exclusive) → `interpret` → `exporter`. `--quick` skips speed and reduces the probe fan-out to reference hosts with `mtr_cycles=1`.

## 13. Config and secrets

`config.py` via `pydantic-settings` + `YamlConfigSettingsSource`, precedence env > `.env` > `config.yaml` > default. All three optional API keys (`IPINFO_TOKEN`, `PEERINGDB_API_KEY`, `ABUSEIPDB_API_KEY`) are `SecretStr | None = None` — a diagnostics tool must run with zero configuration; a missing key downgrades the dependent enrichment to `skipped` with a warning, never fails the run.

`.env` — secrets only (the three keys above). `config.yaml` — timeouts, `probing` (reference/service hosts, ping count, mtr cycles, max hops), `speedtest` (enabled tiers, transfer sizes, CDN fallback URLs), `providers` (base URLs, FireHOL refresh interval), `thresholds` (latency/jitter/loss/bufferbloat good/warn bands), `output` (logs dir, emoji on/off), `watch` (interval, dashboard refresh rate).

## 14. Output

**Filenames:** `report_<ASN>_<YYYYMMDDTHHMMSSZ>.{md,json}` (compact ISO — Windows forbids `:` in filenames), falling back to `report_unknown_…` when ASN lookup fails entirely. Written via temp-file + atomic rename into `./logs/` (gitignored — reports contain external IP, city, coordinates, ISP name).

**JSON top-level keys:** `schema_version, meta{run_id, started_at, finished_at, mode, target, flags, host_os, capabilities}, connection, ip_geo, vpn_assessment, bgp, reputation, latency, path, speed, interpretation{overall_status, overall_score, summary_text, findings}, errors, raw{<source>: <verbatim payload>, ...}`. `raw` stores every provider response verbatim under its source key — this is what actually satisfies "100% of collected data, no truncation," since the typed layer above it can drop fields the raw payload still has.

**Markdown sections:** Header (mode/target/timestamp/overall verdict) → TL;DR (top findings) → Connection & identity → VPN/proxy assessment (verdict + signals table) → ASN & BGP intelligence (upstreams, prefixes, stability, IXPs, ASRank) → Reputation (InternetDB, FireHOL hits, DNSBL if run) → Latency (per-host table + sparkline) → Path/MTR (hop table + ASCII bar, first-loss-jump highlighted) → Speed (down/up, cascade tier used, bufferbloat with plain-language consequence) → Problems & recommendations → Run diagnostics (module status table). ASCII graphs inside fenced code blocks so `rich.markdown.Markdown` doesn't reflow them; emoji (🟢/🟡/🔴) gated behind `output.emoji` config.

## 15. `--compare` and `--watch`

- **`--compare a.json b.json`** (`compare.py`): loads two prior JSON reports, diffs the typed fields (egress IP/ASN, VPN verdict, latency deltas per host, speed deltas, new/resolved Findings), prints a compact before/after table. Read-only, no new probing.
- **`--watch`** (`watch.py`): loop of lightweight runs (reference-host ping/jitter + a reduced traceroute) at a configurable interval, full speedtest only every N cycles (configurable), live-updating Rich table/dashboard in the terminal. Each cycle's summary is appended to the run's JSON log (not a full separate report file per tick) so a `--watch` session produces one time-series artifact, not hundreds of report files.

## 16. Testing strategy

Per project convention — meaningful behavior only, glue untested.

**Test:** `traceparse.py` (all three OS formats incl. BSD multi-IP hops, `!H`/`!N` annotations, cp866-localized Windows output, timeouts, truncated/max-hops-without-arrival); `interpret.py` (threshold→severity mapping, VPN confidence across signal combinations including combos that should *not* fire, bufferbloat grading); `ip_geo.py` normalizers (each provider's shape → common `IpGeo`, from captured fixtures); reputation `127.255.255.x` decoding (regression-critical — this is the false-positive bug found during design, §8); `speed.py` math (bytes+interval→Mbps, `cfL4` header parsing); `probes/latency.py` statistics (jitter/loss/mdev, all-timeout and single-sample edge cases); `exporter.py` (JSON validity with `allow_nan=False`/inf-NaN regression, all-modules-failed run still produces a complete report, filename sanitization); `compare.py` diff logic; cascade ordering (tier1 fails → tier2 used → ... → all-fail yields `status=failed` not an exception, via `pytest-httpx`).

**Skip:** live HTTP, real ICMP, Typer wiring, config loading, `psutil`/`ctypes` calls, `--watch` timing loop.

## 17. Dependencies

```
typer>=0.12          rich>=13.7           httpx[http2]>=0.28
pydantic>=2.7         pydantic-settings>=2.3
pyyaml>=6.0           dnspython>=2.6       psutil>=5.9
[optional] tcptrace = scapy>=2.5      # --tcp-trace only
[optional] ndt7     = websockets>=12  # --ndt7 only
[dev] pytest>=8  pytest-asyncio>=0.23  pytest-httpx>=0.30
```
`icmplib` is Unix-only per its own docs (ignored on Windows) — included as a base dependency, used conditionally by OS. No Ookla pip package dependency (archived); the native binary is an optional runtime dependency the tool detects, never installs.

## 18. Project status

Public GitHub repository, open-source, not sold or bundled into a paid product. License TBD between MIT and Polyform Noncommercial — **Polyform Noncommercial is recommended**, because it's the only option that stays consistent with §6/§8's provider choice: Shodan InternetDB and Spamhaus's free mirrors are non-commercial-use-only, and a permissive license (MIT) would let a downstream commercial fork violate those third-party terms even though the user's own use stays non-commercial. If MIT is chosen instead, README must explicitly flag that the default reputation sources (§8) are non-commercial-use-only and that a commercial fork needs to swap them. This is a licensing decision for the user to finalize before the first public push, not a blocker for implementation.

**Public-repo doc requirements (global CLAUDE.md):** `README.md` + `README.ru.md`, `ARCHITECTURE.md` + `ARCHITECTURE.ru.md`, cross-linked at the top of each ("[Русский](README.ru.md)" / "[English](README.md)"). GitHub issues/PRs/commits stay English-only; code identifiers English-only. These four doc files are created as the first implementation step (project scaffold), before any other code — the "Starting a new project" checklist puts them before the first commit, which the local `.git init` already produced ahead of them; this is corrected in the scaffold task of the implementation plan.
