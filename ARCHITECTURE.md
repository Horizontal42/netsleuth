# Architecture

[Русский](ARCHITECTURE.ru.md)

netsleuth collects network facts from many independent, mostly keyless sources, merges them into typed structures, interprets them with pure functions, and renders two artifacts per run. Collection, interpretation and rendering never mix: every module either gathers data or reasons about already-gathered data, never both.

## Directory layout

```
src/netsleuth/
  cli.py          Typer app: flags, phase orchestration, Rich progress. No business logic.
  config.py       pydantic-settings loader. Precedence: env > .env > config.yaml > default.
  models.py       Every shared dataclass, plus to_jsonable() for serialization.
  orchestration.py  run_module(): timing, timeout, exception -> ProbeError classification.
  netinfo.py      Capability detection and local interface/gateway/MTU/resolver facts.
  iface.py        --interface resolution: adapter name/IP -> BindTarget, pure and tested.
  ip_geo.py       Six-provider identity chain, per-provider normalizers, field-wise merge.
  bgp.py          RIPEstat, CAIDA ASRank, Team Cymru DNS, PeeringDB (disk-cached).
  reputation.py   FireHOL netset cache + prefix lookup, Shodan InternetDB, DNSBL decode.
  stats.py        Pure RTT statistics: loss, min/avg/max, mdev, jitter.
  traceparse.py   Pure text -> TraceHop parsers for Windows, Linux and BSD/macOS output.
  interpret.py    Pure verdict engine: thresholds -> Finding[], VPN scoring, bufferbloat grade.
  speed.py        Cascading speedtest, throughput math, cfL4 header parsing, bufferbloat probe.
  exporter.py     JSON and Markdown rendering, atomic writes into ./logs/. Which
                  artifacts get written is decided by the caller (cli.py), not here.
  alerting.py     Pure webhook-transition contract (should_fire debounce) plus a plain httpx POST for --watch alerts.
  compare.py      --compare: diff two saved JSON reports; render_diff_brief() feeds the automatic vs-previous-run summary.
  history.py      Same-ASN report lookup by filename convention: report_key(), find_previous(), latest_key().
  trend.py        --trend N: aggregates N saved JSON reports into per-label sparkline series.
  metrics.py      collect_metrics() extracts a flat Metric list from a report; render_prometheus()/render_csv() serialize it.
  watch.py        --watch: periodic re-run loop with a live Rich dashboard.
  probes/
    latency.py         Ping fan-out and jitter/loss/mdev/p95/p99 statistics.
    traceroute.py      Cascade: mtr --json -> icmp_win -> icmplib -> system binary text, plus the opt-in tcp_trace tier.
    icmp_win.py        ctypes IcmpSendEcho2 / Icmp6SendEcho2 engine (Windows only).
    dns_leak.py        Per-adapter resolver enumeration, echo probes, ECS detection.
    tls_rtt.py         --tls: TCP RTT + TLS 1.3 handshake + TTFB via two sequential connections.
    dns_advanced.py    --dns-advanced: system DNS vs DoH, transparent-proxy probe on a bogon resolver IP.
    bgp_path.py        --path-diversity: CF-RAY edge colo lookup, international-routing-loop detection.
    prefix_benchmark.py --prefix-bench: ping the first host of a capped sample of the AS's announced prefixes.
    dpi_check.py       --my-server: single-host TCP RST/filtering self-diagnostic. Not a scanner — see Key decisions.
    ecmp.py            --ecmp: pure N-run traceroute diff to spot per-hop load balancing. Backend-agnostic by design.
    pmtud.py           --pmtud: binary-searches the largest DF-set packet that reaches a target, to catch a PMTUD blackhole.
    quic_rtt.py        --quic: QUIC/HTTP3 handshake RTT via the optional aioquic dependency; detects UDP/443 blocking.
    nat64.py           One RFC 7050 AAAA query (ipv4only.arpa) to detect NAT64/464XLAT translation.
    hop_asn.py         Per-hop ASN/AS-name/country/PTR enrichment via Team Cymru DNS, in-run deduped.
    captive_portal.py  Phase-0 gate: three generate_204-style probes for a public-wifi login wall.
```

**File-size exceptions.** The ~200-line guideline (Global Constraints) held for most modules, but these grew past it during implementation and were kept as single files rather than split, because each one is a single cohesive responsibility that splitting would only scatter across more files with a thinner reason to draw the line anywhere in particular:

- `exporter.py` (~910 lines) — JSON and both Markdown languages are renderers of the same report shape; keeping them together is what guarantees the English and Russian reports can never drift on which sections or rows exist. `render_markdown(report, lang="en"|"ru")` and a handful of inline `_t(lang, en, ru)` calls at each string site render both languages from one code path, deliberately, instead of a second renderer file that could silently fall out of sync. This grew by five sections (TLS, DNS advanced, path diversity, prefix bench, DPI check) without changing that argument.
- `cli.py` (~805 lines) — the Typer app, every flag, and the full `diagnose()` phase pipeline; splitting flag parsing from what the flags toggle would just add an import hop.
- `models.py` (~490 lines) — every shared dataclass plus `to_jsonable()`; this is deliberately the one place that defines the report's vocabulary.
- `interpret.py` (~600 lines) — threshold bands, the latency/path/speed/TLS/DNS/DPI/anycast/prefix finding generators, VPN scoring and bufferbloat grading all reason over the same `Finding[]` shape.
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
                +-- bgp || reputation || dns_leak || dns_advanced || path_diversity   (parallel)
                |
                +-- latency || traceroute || tls fan-out        (parallel, semaphore-bounded)
                |
                +-- prefix_benchmark  (opt-in, sequential — isolated from the latency fan-out above)
                |
                +-- dpi_check         (opt-in, sequential — single-host, rate-limited)
                |
                +-- speed                                 (exclusive phase lock)
                |
                +-- interpret  ---> Finding[] + overall verdict
                |
                +-- exporter   ---> logs/report_<ASN>_<ts>.{md,ru.md,json}
```

Three hard concurrency constraints:

1. **Measurement isolation.** The speedtest never overlaps traceroute, ping or API calls — it holds an exclusive phase lock. The single intentional exception is the bufferbloat probe, which overlaps saturation by design, inside `speed.py`.
2. **Bounded traceroute fan-out.** Parallel traceroutes to different targets share early hops and inflate each other's latency, so concurrent traces are capped by a semaphore (`probing.trace_concurrency`, default 2).
3. **The AS prefix benchmark never shares a phase with the reference-host latency fan-out.** Pinging up to `prefix_bench.max_prefixes` (capped at 256, default 32) hosts at once would both skew its own results and pollute the latency numbers measured for the fixed reference hosts in the same window, so it runs as its own sequential, opt-in step (`--prefix-bench`) after phase 3 finishes, never inside `--full`.

## Key decisions

**Failure is a value, not control flow.** Every module call goes through `run_module()`, which times it, enforces a per-module timeout, catches everything except `CancelledError`, and returns a `ModuleResult` with `status` in `ok | partial | failed | skipped`. `asyncio.gather(..., return_exceptions=True)` is a second net at the orchestration layer. No single provider outage can abort a run, and both output formats show every failure explicitly — a report missing its speed section must never look identical to a report where speed was fine.

**Never require elevation.** Capability detection is attempt-based, never OS-assumption-based: try unprivileged datagram ICMP, then raw ICMP, then (on Windows) the `IcmpSendEcho2` API, then fall back to TCP-connect timing and the Cloudflare `Server-Timing: cfL4` header. Worst case, the tool still produces a full report and states the degradation once, plainly, with the one-line remedy.

**Windows traceroute uses the Win32 ICMP API, not `tracert.exe` text.** `IcmpSendEcho2` from `Iphlpapi.dll` is the same unprivileged API `tracert.exe` uses internally. Driving it through `ctypes` gives per-hop RTT, TTL-expiry detection and real timeout handling with no Administrator, no Npcap and no third-party dependency — strictly better than parsing a localized three-probe text table.

**Text parsing is a last resort, and parses by line shape.** When the system binary is the only option, `traceparse.py` matches on structure (leading hop integer, RTT tokens, IP regex) and never on header or footer wording, because Windows `tracert` output is code-page dependent — cp866 on Russian Windows, not UTF-8. BSD/macOS additionally emits multiple IPs per hop and `!H`/`!N`/`!X` annotations that Linux does not, so the three parsers are genuinely separate.

**Latency never parses `ping` text.** That would mean three more locale-dependent parsers for no benefit. Every `PingResult` is tagged with the method used, because TCP "loss" (connection failure rate) and ICMP loss are different metrics and must never be silently conflated.

**Reputation defaults to sources that do not learn what you are checking.** FireHOL netsets are downloaded once, cached, and matched locally — no runtime query, no rate limit, no disclosure. Shodan InternetDB tells a home user something actionable (an exposed router, a forgotten port-forward) far more often than a mail blocklist does. Classic DNSBLs are opt-in behind `--dnsbl`.

**DNSBL responses in `127.255.255.0/24` are errors, not listings.** Spamhaus returns `127.255.255.254` for "you queried through a public resolver" — which is the case for anyone on 1.1.1.1 or 8.8.8.8 — and `127.255.255.255` for "rate limited". A naive "any `127.x.x.x` means listed" implementation red-flags most users. Both are surfaced as *result unavailable*, never as a finding.

**`--interface` binds where the code structurally can, drops where it structurally can't, never runs unbound and silent.** Every httpx-based provider client can bind an exact local address (`local_address=` on the transport) — cheap and solid. The Ookla binary tier passes `--interface`/`--ip` through to the external process. `icmp_win` uses `IcmpSendEcho2Ex` (which adds a `SourceAddress`) instead of `IcmpSendEcho2` only when a bind is forced, so the unforced path is byte-for-byte unchanged. The one structural dead end is Windows `tracert.exe`, which exposes a source-address override for IPv6 only, never IPv4 (`-S` is documented IPv6-only in its own usage text) — `filter_trace_tiers()` drops that tier rather than let it silently measure the OS-default path under a report claiming a forced adapter. `netinfo.collect_local_net()`'s own observation of the OS's real default route is deliberately left untouched by the flag: the report needs to show *both* the forced adapter and what the OS would have chosen on its own, and overwriting the observation would turn the VPN gateway/tunnel-interface signals into a tautology (force the VPN adapter, get "VPN confirmed" for free).

**An interface with no route to the internet is a diagnostic answer, not an error.** Resolving an unknown/down/addressless adapter aborts immediately (`typer.BadParameter`, every adapter listed) — that is bad *input*. But an adapter that resolves fine and turns out to carry nothing is exactly the kind of thing this tool exists to surface, so the run proceeds, every probe fails into the normal `unavailable`/`timeout` classification, and the report says so plainly rather than pretending to be a default run.

**Bulk RIPEstat endpoints are always bounded.** `routing-history` and friends return 10 MB+ payloads for large ISPs, so every such call carries `max_rows` and a timeframe from `config.yaml`.

**PeeringDB is cached to disk.** Anonymous limits are 20 requests/minute with large responses throttled to one per hour, so a response is never re-fetched within a run and persists in `.cache/` between runs for `providers.peeringdb_cache_hours`.

**The JSON dump carries a `raw` section.** Every provider response is stored verbatim under its source key. The typed layer above it necessarily drops fields; `raw` is what actually satisfies "100% of collected data, no truncation".

**Why the DPI check is not a port scanner.** `probes/dpi_check.py` is, mechanically, code that opens TCP connections to an IP on several ports — the same primitive a port scanner uses. The difference between a self-diagnostic and a scanner is the constraints wrapped around that primitive, and they are load-bearing, not cosmetic:

1. **The target is only ever the string the user typed after `--my-server`.** `check_dpi(target, resolved_ip, ports, ...)` takes both as required positional-or-keyword arguments with no default — there is no code path that fills them in from `IpGeo.ip`, `CfTrace.ip`, `--target`, or `BgpIntel.announced_prefixes`. `tests/test_dpi_check.py` pins this via `inspect.signature`.
2. **The port list is fixed and short.** `dpi_check.ports` in `config.yaml` defaults to six ports and is capped at 16 by a pydantic validator in `config.py` — there is no `--ports`/range flag, and raising the cap requires editing and redeploying the config, not passing a CLI argument.
3. **One host per run.** `--my-server` takes a single value; CIDR input is rejected outright in `cli.py` before `Options` is even built (`"this is a single-host self-diagnostic, not a network scanner"`).
4. **Rate-limited by construction.** `asyncio.Semaphore(dpi_check.concurrency)` (capped at 4) plus `asyncio.sleep(delay_between_ports_seconds)` between probe starts; one attempt per port, no retries.
5. **Consent is printed, not just documented.** Before probing, `cli.py` prints which host and how many ports are about to be touched and that this must be a host the user owns or is authorised to test — the same pattern as the existing `--tcp-trace` warning, not the file-marker consent `--ndt7` uses, because there's no third-party data disclosure here, only a question of authorization.
6. **The target is audited.** `meta["dpi_target"]` in every JSON report records exactly what was checked.

The AS prefix benchmark (`probes/prefix_benchmark.py`) gets the same treatment for the same reason at a different scale: pinging the first host of *every* prefix a large ISP announces is mass probing of a network the user does not necessarily own. `prefix_bench.max_prefixes` is capped at 256 in a validator (default 32), the probe is ICMP-only (never TCP-connect), and it is never enabled by `--full` — only by explicit `--prefix-bench`.

**TLS handshake timing uses two sequential connections, not `ssl.SSLObject.start_tls()` on one.** `probes/tls_rtt.py` opens a plain TCP connection first (`tcp_connect_rtt()`, already used by `latency.py`) to get a TCP-only baseline, then a second `asyncio.open_connection(..., ssl=...)` to the same host and subtracts the baseline from the second connection's total time to get `tls_handshake_ms`. This slightly overstates the true handshake time (a second TCP handshake happens too) but avoids the complexity of upgrading one live connection mid-flight, and the report says explicitly, in a footnote under the table, that the number is derived by subtraction — not presented as a lab-grade measurement.

**`dns_advanced.py` and `dns_leak.py` answer different questions and must not merge.** `dns_leak.py` asks "where do my DNS queries physically exit to the internet" (echo probes, resolver-ASN-vs-egress-ASN comparison) and feeds the VPN-confidence scoring. `dns_advanced.py` asks "how fast and how honest are the answers" (system vs DoH timing and content) and feeds its own findings. They share nothing but `dnspython`; a shared helper (`resolver_for`-style) was deliberately not extracted, because the one place they'd overlap (resolver construction) is three lines each and not worth a coupling.

**A resolver answering differently from DoH is not, by itself, evidence of anything.** Any CDN behind geo-DNS or ECS legitimately hands different resolvers different IPs for the same name. `dns_advanced.compare_answers()` records the difference as plain text; `detect_poisoning()` only escalates to a finding when the *system* resolver's answer is itself bogus (`0.0.0.0`, loopback, private, or RFC 5737) while DoH's answer is a normal public address — that specific asymmetry, not mere disagreement, is what a poisoned/hijacked response looks like.

**The Cloudflare colo→city/country table is a curated ~30-entry dictionary, not a full IATA database.** Pulling in a full airport-code package for this one lookup would be a new dependency for a feature that only needs to answer "is the edge PoP in a different country than the client" for a modest, CIS/Europe-weighted set of colos. An unrecognized code renders as "unknown" rather than guessing.

**The international-routing-loop check compares the client's own geolocated country against the edge PoP's country — nothing else.** An earlier version of `detect_international_loop()` also required the *target's* resolved-IP geolocation to match the client's country before it would fire, on the theory that this ruled out an unrelated confound. In practice nothing ever populated that field, so the check could never fire at all — caught by manually running `--path-diversity` end-to-end and inspecting the JSON output, not by any unit test, since the unit tests exercised the function directly and simply supplied the value the buggy production code path never provided. The lesson generalized: two inputs beat three when the third can't reliably be filled in, and a smoke run of new opt-in flags belongs in the same pass as the unit tests, not after them.

**CGNAT detection uses three evidence paths, not one.** A user behind a home router sees a private `192.168.x.x` address locally while carrier-grade NAT (RFC 6598, `100.64.0.0/10`) lives one hop further up — checking only `LocalNet.local_ipv4` would miss the common case entirely. `cgnat_findings()` checks the local address, then the default gateway, then every traceroute hop, in that order, and records which one fired as the finding's evidence string.

**NAT64/464XLAT is detected the RFC 7050 way, not by checking the client's own address.** The well-known synthesis prefix `64:ff9b::/96` is where a NAT64 resolver *embeds* an IPv4 destination, never something the client's own egress address falls into — an earlier design that checked the egress IPv6 against that prefix would never fire. The correct probe is a single AAAA query for `ipv4only.arpa`: its A records are two fixed addresses (`192.0.0.170`/`.171`), and a DNS64 resolver synthesizes an AAAA answer embedding one of them in the network's actual (often ISP-specific) `/96` prefix; a real dual-stack network returns no AAAA for that name at all.

**The first traceroute hop is diagnosed separately from the rest of the path.** Loss or latency at hop 1 means the user's own router or Wi-Fi, not the ISP or anything downstream — `path_findings()` takes an optional `LocalNet` and, when supplied, compares the first hop's IP against the OS-observed default gateway before running the existing mid-path loss-jump logic, so the two questions ("is my LAN fine" vs "where does the wider path degrade") stay structurally separate rather than one drowning out the other.

**Per-hop ASN enrichment is a separate phase after the trace completes, not folded into traceroute itself.** `TraceHop.asn`/`as_name` existed in the model since the original design but were never populated by any writer — `probes/hop_asn.py::enrich_hops()` fills them (plus a new `country` field and a PTR fallback for backends that don't resolve hostnames themselves) by collecting the unique set of hop IPs across every trace and firing one Team Cymru DNS query pair per IP, deduped in-run. This runs as its own `run_module("path_enrich", ...)` step in `cli.py` after the latency/path/TLS fan-out and before speed, and mutates the already-collected `TraceHop` objects in place; a lookup failure folds into that step's warnings only; it can never downgrade the trace's own `ModuleResult.status`. Team Cymru's DNS service has no rate limit (unlike the `cached_json()`-wrapped RIPEstat/CAIDA calls), so no disk cache is needed — only in-run dedup of repeated hop IPs.

**Captive portal detection tags, never short-circuits.** `ModuleResult.status` is informational everywhere else in the pipeline, and nothing in `diagnose()` branches on it — introducing the codebase's first status-driven control flow for this one feature would contradict "failure is a value, not control flow" above. A captive portal is also rarely total: DNS and ICMP often pass while only HTTP is intercepted, and a short-circuited run would produce a report indistinguishable from a dead link. So `probes/captive_portal.py` runs as Phase 0, before everything else, and on detection adds a `crit` finding plus a banner at the top of the report — every other phase still runs and is honestly labeled as measured from behind the portal, which is more information than refusing to measure at all.

**The three default captive-portal check URLs must share one success shape, and picking them is not interchangeable.** `check_captive_portal()` expects every URL to behave like a `generate_204` endpoint: HTTP 204 with an empty body on success. Mozilla's `detectportal.firefox.com/success.txt` was tried as a third default and immediately produced a false positive on a real network — its *correct*, non-portal response is HTTP 200 with the body `success`, which is indistinguishable from `classify_portal_response()`'s "200 with a body" portal signal. Caught by the same live-smoke-test discipline as the international-loop bug above, not by a unit test (the unit tests fed the function literal response shapes and never modeled a real endpoint's actual behavior). Fixed by swapping in a second genuine `generate_204` endpoint (`clients3.google.com`) instead of teaching the classifier a second success shape — one uniform contract across all check URLs is simpler than a per-URL expected-body table for three entries.

**Speedtest server geo-sanity compares countries, not coordinates.** The original design called for a haversine distance in km between the client and the speedtest server, which needs both ends' lat/lon. Live inspection of the bundled Ookla CLI's own JSON output (`speedtest.exe --format=json`) showed its `server` object carries `location` (a city name) and `country`, never `lat`/`lon` — that's the documented schema, not a version quirk. `speed_findings()` compares `SpeedResult.server_country` against the client's own geolocated country instead: coarser than a distance, but real, always available when a tier reports a country, and it still catches the case that matters (the test hit a server in another country entirely).

**TLS certificate handshake tries verified first, only degrades to `CERT_NONE` on a validation failure.** `probes/tls_rtt.py::tls_context(verify: bool)` defaults to a real, unmodified `create_default_context()` — a change from the tool's original always-`CERT_NONE` posture. `measure_tls()` attempts a verified connection first; only on `ssl.SSLCertVerificationError` does it retry unverified (re-timing the retry, since the failed attempt's duration isn't representative of a real connection). This is the only way to get `subject`/`issuer`/`notAfter` at all: Python's `getpeercert()` returns `{}` for an unvalidated chain, populating the parsed dict only when the certificate actually verified — `getpeercert(binary_form=True)` (the raw DER, hashed into `cert_sha256`) is the one thing available either way. The fingerprint is the SHA-256 of the **full DER certificate, not the SPKI** — extracting just the subject-public-key-info needs the `cryptography` package, a new dependency this feature doesn't need; the report footnote tells a user comparing against an externally-pinned value to compute it the same way (`openssl x509 -outform DER | sha256sum`).

**Pinning is configured, not flagged.** `tls.pinned_fingerprints` (host → expected SHA-256, capped at 32 entries, each normalized and hex-validated by a pydantic validator) follows the same posture as `dpi_check.ports`: raising the list requires editing and redeploying the config, not a `--pin` CLI argument on a diagnostic tool that anyone could point at anything.

**Prometheus and CSV are one extraction, two serializations — not two renderers.** `metrics.py::collect_metrics(report) -> list[Metric]` does the per-section special-casing a flat walk of the report dict can't (latency needs a label/host/method triple, TLS a label/host pair, path hops a target/ttl/ip/asn quadruple) as a single pure `dict -> list[Metric]` function; `render_prometheus()` and `render_csv()` are then ~15 lines each, formatting the same list two ways. `FORMAT_EXTENSIONS` (`config.py`) is still the single source of truth both `cli.py::parse_formats()` and `config.py::Output._normalize_formats()` key off of — adding `"prom"`/`"csv"` there was the only wiring point.

**Same-ASN auto-diff runs before `write_report()`, or the current run would diff against itself.** `history.find_previous()` globs `./logs/` for `report_{key}_*.json` using the exact same `sanitize_name()`/timestamp convention `exporter.report_filename()` already writes, so the lookup key can never drift from what's actually on disk. It only fires when this run is itself writing JSON (there'd be nothing to diff against on a future run otherwise) and only prints a one-line note — never a warning — when JSON isn't in this run's formats, since silence is correct on every other skip path (first run ever, or a prior run that didn't write JSON). `compare.py::render_diff_brief()` exists because the full `render_diff()` table is too long to print unbidden after every run; it surfaces only the ASN/IP change, the single worst latency delta, the download delta, and new/resolved finding counts.

**`--trend` needs no live network call to find "this network's" history.** Rather than re-running identity detection just to know which ASN's reports to load, `history.latest_key()` reads it back off the newest `report_*.json` filename already on disk — the same file-naming convention already encodes it, and a read-only historical view has no reason to touch the network at all.

**`--watch` had no verdict at all before this, and giving it one came first.** `watch.py::run_watch()` only ever fanned out pings (plus an occasional speedtest) and rendered raw numbers — `interpret` was never imported. Wiring alerting to "a verdict transition" was impossible until there was a verdict to transition between, so `summarize_cycle()` now reuses the exact same pure `latency_findings()`/`speed_findings()`/`overall_verdict()` functions the one-shot report already uses, gaining `status`/`score`/`finding_ids` on every tick — a real improvement to the dashboard on its own, independent of whether a webhook is ever configured.

**The whole webhook debounce contract lives in one pure function.** `alerting.should_fire(previous, current, last_fired_at, now, min_interval_s, fire_on)` decides everything: fires only on an actual transition (never on the first tick, since there's nothing to transition from), only into a state the user opted into (`watch.webhook_on`), and only after `webhook_min_interval_seconds` (floored at 30 in a validator) has elapsed since the last firing — a flapping link cannot spam the endpoint every tick. Recovery (`crit`/`warn` → `ok`/`info`) is its own opt-in token (`"recovered"`), not implied by configuring `"crit"`, because a user who wants to know about outages doesn't necessarily want a second ping when they end.

**The webhook payload is a flat JSON body, not shaped for any particular chat platform.** `alerting.build_payload()` returns `{tool, asn, at, previous, current, score, findings, host}` — Slack/Discord-specific formatting is a concern for whatever receives the POST, not for netsleuth. `post_webhook()` swallows every `httpx`/`OSError` failure and returns `False`; a dead webhook endpoint must never interrupt the monitoring loop it's supposed to be watching.

**ECMP detection diffs N independent traceroute runs, not one run's per-hop annotations.** BSD's `traceparse.py` already records a same-TTL-different-router signal as an `alt:` annotation, but that concept can't generalize: mtr's JSON aggregates cycles and discards per-cycle next-hop variance, `icmp_win`/`icmplib` send exactly one probe per TTL by construction, and the Linux system-traceroute parser doesn't model multi-IP hops even though the text can contain them. A finding that only ever fires on macOS and Linux-with-the-system-binary would be worse than not having it. `probes/ecmp.py::detect_ecmp()` instead takes N independently-run `TraceResult`s for the same target and diffs which IP appeared at each TTL across runs — this works identically regardless of which backend produced each trace, and the function itself never touches capability detection or backend choice at all.

**`--ecmp` is opt-in and capped, and never joins `--full`.** It multiplies traceroute traffic against the same target by `ecmp.runs` (default 3, capped at 5) — per the trace-concurrency reasoning already established (parallel traces to the *same* target inflate each other's latency worse than parallel traces to different targets), this is deliberately sequential per target and shares one fresh semaphore across `ecmp.max_targets` (capped at 3) targets, run only after the main latency/path/TLS fan-out has already finished.

**IPv6 latency rides the existing ping fan-out with a distinct label, not a parallel `latency_v6` section.** `probing.reference_hosts_v6` (literal IPv6 addresses) are fed into the same `ping_fanout()` used for IPv4, labeled `"<label>-v6"`, and the results are appended to `modules["latency"].data` after the Phase 3 fan-out — `exporter._latency()`, `metrics.collect_metrics()` and `compare.py` all key everything off `PingResult.label` already, so this needed zero changes to any of them. `interpret.dual_family_findings()` pairs a `"cloudflare-dns-v6"` row back to its `"cloudflare-dns"` twin by stripping the suffix, entirely in application code — the report schema itself doesn't know IPv6 exists as a separate concept.

**No family-detection code was needed for the IPv6 ping path itself, because the existing fallback chain already handles it correctly.** `icmp_win`'s `ping_samples_win()` calls `socket.gethostbyname()`, which is IPv4-only and raises `socket.gaierror` on an IPv6 literal — caught by `latency.py::ping_host()`'s existing bare `except Exception: backend = "tcp"`, which then correctly pings the v6 literal via `asyncio.open_connection` (family-agnostic). On Linux/macOS, `icmplib.async_ping()` natively detects the address family from the literal. Verified live with `--ipv6` forced on a v6-unreachable host: every v6 row correctly fell back to `method="tcp"` and reported 100% loss, exactly as designed, no crash.

**IPv6 traceroute and `--path-diversity` are deliberately out of scope for this phase.** Extending the trace cascade and `bgp_path.py` to a second address family is real additional work (`icmp_win`'s trace tier is IPv4-only for the same `gethostbyname()` reason above, though `run_cascade()`'s per-tier exception handling means it would at worst fall through to `system_traceroute` rather than corrupt a report) that doesn't share the "tag with a label, touch nothing downstream" trick latency did — left as a documented follow-up rather than expanding this phase to match.

**PMTUD stays unprivileged by reusing the same DF-flag hook the ICMP capability detection already carries, and falls back to the system `ping` binary rather than hand-rolled raw sockets on Unix.** On Windows, `IcmpSendEcho2`'s `IP_OPTION_INFORMATION.Flags` field already existed in `icmp_win.py` (unused until now) — `echo_once()` gained a `df: bool` parameter that sets `IP_FLAG_DF` (0x02), and `classify_status()` gained `IP_PACKET_TOO_BIG` (11009), the status Windows returns when a router replies "fragmentation needed." No new privilege is required: this is the same unprivileged `IcmpSendEcho2` API the rest of the ICMP tier already uses. On Linux/macOS, rather than constructing raw ICMP echo requests by hand (version-dependent kernel checksum/identifier quirks on unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` sockets make that fragile in ways this project's author had no way to verify without those platforms on hand), `probes/pmtud.py` shells out to the system `ping` binary with `-M do -s <size>` (Linux) or `-D -s <size>` (macOS/BSD) — the same subprocess-and-parse pattern `traceroute.py`'s system tiers already use, and `ping`'s DF/size flags are stable, well-documented ping(8) behavior rather than something this project needs to reverse-engineer.

**A local "frag needed" failure and a genuine on-path ICMP response are both treated as the same "reduced" signal, not distinguished.** Linux `ping -M do` fails immediately with a local error when the kernel already has the path MTU cached, without ever sending the oversized packet; when it doesn't have a cached value, an actual router's "fragmentation needed" ICMP produces a different message. `_probe_unix()` matches loosely (`"frag"` or `"too long"` anywhere in the combined stdout/stderr, case-insensitive) precisely because the exact wording differs across ping implementations and situations — matching on the presence of the signal, not its precise phrasing, is the same "parse by shape, not exact wording" principle `traceparse.py` already established for traceroute output.

**The classic PMTUD blackhole distinction is "did anything tell us why."** `classify_pmtu()` calls a discovered MTU `"reduced"` when a frag-needed signal was seen at any point during the search (PMTUD is working, the path is just narrower — normal behind a VPN/tunnel) and `"blackhole"` only when large packets simply vanish with no ICMP reply at all (the actual VPN/PPPoE-router-misconfiguration symptom: "SSH connects then hangs"). `path.pmtu_below_iface_mtu` is a separate, always-checked finding — a path MTU narrower than the local NIC's own MTU is exactly what makes this class of problem invisible to every locally-run tool.

**QUIC/HTTP3 is the one feature that adds a real dependency, and it stays optional the same way `tcptrace`/`ndt7` already do.** `aioquic` lands as a `[project.optional-dependencies]` extra (`uv sync --extra quic`), never a hard dependency of the base install; `probes/quic_rtt.py::measure_quic()` imports it lazily inside the function (the same `_tier_tcp_trace` pattern `traceroute.py` already uses for scapy), so an `ImportError` is a per-target skip, not a crash, and `_quic_section()` reports a clear `quic.unavailable`-style warning naming the install command rather than silently doing nothing. `aioquic`'s own `connect()` handshake — verified against the actually-installed 1.3.0, not assumed — completes before the async context manager yields, so unlike the TLS RTT probe's two-connection subtraction trick, QUIC's handshake time is measured directly and the report says so.

**QUIC does not support `--interface`, and the report says so rather than silently measuring the OS-default path.** `aioquic.asyncio.client.connect()`'s signature (checked against 1.3.0) takes `local_port` but no `local_host`/source-address parameter at all — there is no structural way to honor a forced adapter here, unlike every other probe in this codebase. `_quic_section()` adds a warning to that effect whenever `options.bind` is set, the same "never runs unbound and silent" posture `--interface`'s Key Decision above establishes for Windows `tracert`.

**A blocked-vs-unreachable distinction is the actual payoff, not the raw handshake number.** `quic_verdict(quic_ok, tcp_ok)` is the pure center of the feature: QUIC failing while a plain TCP connection to the same host on the same port succeeds means the network is specifically dropping or throttling UDP/443 — the network silently degrading Chrome/YouTube's HTTP/3 preference in a way no TCP-based diagnostic would ever surface. Both failing is ordinary unreachability, already covered by the existing TCP/latency findings, so `quic_findings()` stays silent in that case rather than duplicating it.

**Python 3.14 is the floor, not 3.10.** The project moved off `>=3.10` when this batch of probes was added; none of the new code actually depends on a 3.11+-only construct (`ssl.SSLObject.start_tls()`, `asyncio.timeout()`, `datetime.UTC`) — the two-sequential-connection TLS design above was chosen independently of what the interpreter allows. The version floor moved because there was no longer a reason to hold it back, not because a specific new feature required it.

## Storage

- `./logs/report_<ASN>_<YYYYMMDDTHHMMSSZ>.{md,ru.md,json,prom,csv}` — the artifacts selected by `--format`/`output.formats` (default: English Markdown only; `all` writes all three: English Markdown, a full Russian translation with identical structure, and the JSON dump — English only, no `.ru.json`). When both Markdown languages are written they cross-link each other at the top, the same way `README.md`/`README.ru.md` do; writing only one skips the cross-link rather than pointing at a file that doesn't exist. `<ASN>` is the target's subject in target mode (an ASN, IP or domain) and the local egress ASN in auto mode. Compact ISO timestamps because Windows forbids `:` in filenames. Falls back to `report_unknown_…` when the ASN lookup fails entirely. Written temp-file-plus-`os.replace()`, always atomic. Gitignored: reports contain the external IP, city, coordinates and ISP name.
- `./logs/watch_<ASN>_<YYYYMMDDTHHMMSSZ>.json` — one time-series artifact per `--watch` session, not one report per tick.
- `./.cache/firehol/*.netset` — downloaded blocklists, refreshed per `providers.firehol_refresh_hours`.
- `./.cache/pdb-net-<asn>.json`, `./.cache/pdb-netixlan-<net_id>.json` — PeeringDB responses, valid for `providers.peeringdb_cache_hours`.
- `./config.yaml` — all non-secret settings. `./.env` — the three optional API keys and nothing else.

## Configuration

`config.py` builds a pydantic-settings `Settings` object whose sources are ordered **init > environment > `.env` > `config.yaml` > field default**. The three API keys are `SecretStr | None = None` at the top level: a diagnostics tool must run with zero configuration, so a missing key downgrades the enrichment that needs it to `skipped` with a warning and never fails the run.

Several sections back the L4-L7 probes, all opt-in at the CLI level; the ones whose target list or sweep range could otherwise become mass probing carry a validator-enforced ceiling: `prefix_bench` (`max_prefixes` capped at 256), `dpi_check` (`ports` capped at 16 entries, `concurrency` capped at 4), `captive_portal` (`check_urls` capped at 4), `tls` (`pinned_fingerprints` capped at 32 entries), `ecmp` (`runs` capped at 5, `max_targets` capped at 3), `pmtud` (`targets` capped at 2, `max_bytes` capped at 9000), `quic` (`targets` capped at 4). `dns_advanced` and `path_diversity` are plain opt-in flags with no sweep range to cap.

## Tests

`uv run pytest -q`. Roughly 880 tests covering the parsers, normalizers, verdict engine, DNSBL decoding, throughput math, ping statistics, jitter percentiles, serialization and the report diff. Glue is deliberately untested: live HTTP, real ICMP, Typer wiring, `psutil`/`ctypes` calls and the `--watch` timing loop. Traceroute fixtures live in `tests/fixtures/traceroute/{windows,linux,darwin}/` and include a cp866-encoded Russian Windows sample, because that encoding is exactly what breaks naive parsers. DoH response fixtures (RFC 8484 JSON form) live in `tests/fixtures/api/doh_*.json` alongside the other provider fixtures.
