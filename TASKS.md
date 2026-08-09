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

## In Progress

- Nothing

## Next

- Consider publishing to PyPI: decide on the distribution name, add a release workflow, and confirm the `tcptrace`/`ndt7` extras install cleanly from a wheel rather than from the repo.
- Revisit the opt-in extras' UX. `--ndt7` currently prints its consent notice and prompts on every interactive run, and `--tcp-trace` prints its privilege warning unconditionally. Decide whether consent should be remembered (a flag in `config.yaml`, or a marker in `.cache/`) so a repeat user is not re-prompted, and what the right behaviour is when stdin is not a TTY.
- Fix adapter-name mojibake in the DNS-leak table: a non-ASCII Windows adapter name (seen on this dev machine: a Bluetooth virtual adapter) renders as cp1251/cp866-corrupted garbage in both the English and Russian reports. Pre-existing bug in `netinfo.py`'s per-adapter resolver enumeration, not introduced by the Russian-report work — needs its own investigation into what encoding Windows actually hands back for adapter friendly names.
- `dual_stack_note` and other free-text notes generated outside `interpret.py`/`reputation.py`/`probes/dns_leak.py` still render in English inside the Russian report (only `Finding`, `Reputation`, `DnsLeak` carry `_ru` fields today). Low-traffic edge case; extend the same inline-sibling pattern if it turns out to matter.

## Blocked

- Nothing
