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

## In Progress

- Nothing

## Next

- Finalize the license: MIT vs Polyform Noncommercial (spec §18). Polyform is the recommendation, because Shodan InternetDB and the free Spamhaus mirrors are non-commercial-use-only and MIT would let a downstream commercial fork violate those terms. If MIT wins, add the caveat to both READMEs. Replace the placeholder `LICENSE` before the first public push.
- Consider publishing to PyPI: decide on the distribution name, add a release workflow, and confirm the `tcptrace`/`ndt7` extras install cleanly from a wheel rather than from the repo.
- Revisit the opt-in extras' UX. `--ndt7` currently prints its consent notice and prompts on every interactive run, and `--tcp-trace` prints its privilege warning unconditionally. Decide whether consent should be remembered (a flag in `config.yaml`, or a marker in `.cache/`) so a repeat user is not re-prompted, and what the right behaviour is when stdin is not a TTY.

## Blocked

- Nothing
