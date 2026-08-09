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
- End-to-end smoke test across `--quick`, `--full` and `--target` modes — caught and fixed five live-network defects (egress_v4 mislabeled on a dual-stack host, the same for asn-target identity lookups, target-mode report filenames using the local ASN instead of the target, cf-trace's own IP leaking into a target lookup, a skipped module's warning not reaching its Markdown placeholder) plus one flaky test (Windows mtime clock skew in the PeeringDB cache)
- Documentation freshness pass against the final module and flag set
- License finalized as PolyForm Noncommercial 1.0.0 — Shodan InternetDB and the free Spamhaus mirrors are non-commercial-use-only, and this license keeps every downstream fork inside those same terms. Real license text landed in `LICENSE`, README/README.ru.md updated, `pyproject.toml` carries the SPDX identifier
- Russian Markdown report (`report_<ASN>_<ts>.ru.md`), written alongside the English one on every run, same structure, same tables, same numbers, cross-linked with its English sibling. `Finding`/`Reputation`/`DnsLeak` carry optional `_ru` sibling fields set alongside the English ones at each construction site; `exporter.py` renders both languages from one code path via `render_markdown(report, lang=...)` and inline `_t(lang, en, ru)` calls, so the two reports cannot structurally drift. Module skip/warning reasons are translated too (small exact-match dict in `exporter.py`)
- Fixed adapter-name mojibake in the DNS-leak table: `netinfo.py`'s `_resolvers_windows()` read PowerShell's redirected stdout as text, but neither `$OutputEncoding` nor `[Console]::OutputEncoding` reliably control that encoding once stdout is a pipe rather than a real console — non-ASCII adapter names came back corrupted no matter which codec was guessed on decode. Fixed by having PowerShell UTF-8-encode and base64 its own output before printing, so the pipe only ever carries ASCII; Python base64-decodes then UTF-8-decodes. Verified live: a Bluetooth virtual adapter's Russian display name now renders correctly in both report languages
- Closed the remaining Russian-report gap for `dual_stack_note`: `ip_geo.dual_stack_mismatch()` now returns an `(en, ru)` pair instead of a single English string; `_connection` in `exporter.py` picks the right one by `lang`. The English copy still goes into `ModuleResult.warnings` for the Run-diagnostics table (that surface stays English — low-traffic, documented)
- `--ndt7` now remembers consent in a `.cache/ndt7_consent` marker file so a repeat interactive run is not re-prompted; a non-TTY run still proceeds without asking (unchanged, correct for CI/scripted use). `--tcp-trace`'s warning stays an unconditional informational print — it is not a privacy consent gate like NDT7's, just a capability notice
- Added `.github/workflows/release.yml`: builds on every `v*.*.*` tag, runs the full test suite, verifies the `tcptrace`+`ndt7` extras install cleanly from the built wheel. The actual PyPI publish step is commented out and gated behind a separate, manually-approved job — **not run**, because the distribution name `netcheck` is already taken on PyPI by an unrelated project (see Blocked below)

## In Progress

- Nothing

## Next

- Nothing outstanding beyond what's Blocked.

## Blocked

- **PyPI publishing needs a new distribution name.** `netcheck` is already registered on pypi.org by an unrelated project ("Netchecks" by hardbyte — a cloud-native network-assertion tool, active since 2022, most recent release checked May 2026). This project's own name cannot be freed up; a different name must be chosen before `.github/workflows/release.yml`'s publish job can be enabled (update `pyproject.toml`'s `[project] name`, then set up PyPI Trusted Publishing for the new name). Needs the user's call — not a decision to make unilaterally.
