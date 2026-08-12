# netsleuth

[Русский](README.ru.md)

Cross-platform CLI for deep network diagnostics: who your ISP actually is, whether a VPN is really carrying your traffic, where the path degrades, and what your line actually delivers.

```console
$ netsleuth --quick
netsleuth 0.1.0 · auto mode · Windows
Verdict: ok (100/100) — No problems found on this connection.
Report written to logs/report_AS64500_20260808T191200Z.md
```

Everything else — egress ASN, VPN verdict, latency, path, speed — lives in the report it just wrote, not on the console; the terminal only tells you the headline and where to look. By default that's a single English Markdown file; `--format` controls exactly which artifacts get written (see Handy things below).

## Install

Requirements:

- Python 3.14 or newer
- Windows, Linux or macOS
- Internet access (netsleuth is a network tool; it degrades gracefully but cannot do much offline)
- Optional: the native Ookla `speedtest` binary on `PATH` for the best bandwidth tier
- Optional: `mtr` on `PATH` for the best path data

```bash
git clone https://github.com/Horizontal42/netsleuth
cd netsleuth
uv sync
uv run netsleuth
```

Want `--tcp-trace` and `--ndt7` too? They're optional extras, not installed by default:

```bash
uv sync --extra tcptrace --extra ndt7
```

Without `uv`:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
netsleuth
```

No configuration is required. Copy `.env.example` to `.env` only if you have optional API keys.

### Getting the optional extras per platform

None of this is required — netsleuth degrades gracefully without any of it — but each optional tool is fetched differently depending on your OS:

- **`uv`** itself: `curl -LsSf https://astral.sh/uv/install.sh | sh` on Linux/macOS; `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"` on Windows.
- **`mtr`** (better path data): `sudo apt install mtr` (Debian/Ubuntu), `sudo dnf install mtr` (Fedora), `sudo pacman -S mtr` (Arch), `brew install mtr` (macOS). No Windows build exists — the traceroute cascade just skips this tier there and falls back to the Windows ICMP API automatically, no action needed.
- **Ookla `speedtest`** (best bandwidth tier): install Ookla's own CLI binary from their official site or your OS package manager — not the unrelated community `speedtest-cli` Python package, netsleuth specifically shells out to Ookla's binary and parses its `--format=json` output.
- **Npcap/libpcap** (only for the `--tcp-trace` extra): on Windows install Npcap; on Linux libpcap usually ships with the distro already, but sending raw packets as a non-root user needs `sudo setcap cap_net_raw+eip $(readlink -f $(which python3))` (or just run under `sudo`); on macOS libpcap is built in but scapy still needs to run as root (`sudo netsleuth --tcp-trace`).

## What it does

- **Captive portal check** — runs first, before anything else: three `generate_204`-style probes catch a public-wifi login wall before it makes every other measurement look like a broken connection.
- **Identity** — egress IPv4 *and* IPv6, reverse DNS, ASN, organisation, geo, and whether the address looks residential, mobile, hosting or business. Cross-checked across six independent providers so one rate limit does not blank the answer. Also flags carrier-grade NAT (RFC 6598) and NAT64/464XLAT translation (RFC 7050) when present.
- **VPN / proxy assessment** — a weighted verdict (`none` / `likely` / `confirmed`) built from tunnel interfaces, MTU anomalies, gateway-vs-egress mismatch, Cloudflare WARP flags, provider proxy/hosting flags, PeeringDB network type, timezone-vs-geo mismatch, and DNS resolver ASN mismatch.
- **DNS leak test** — enumerates resolvers *per network adapter*, so it catches the classic case where the tunnel adapter is clean but the Wi-Fi adapter still holds the ISP resolver. Also detects EDNS Client Subnet leakage.
- **BGP intelligence** — upstreams, peers, downstreams, announced prefixes, route stability, IXP presence, and CAIDA ASRank customer-cone size.
- **Reputation** — locally cached FireHOL blocklists (no query leaves your machine), Shodan InternetDB exposure, and optional classic DNSBL zones.
- **Latency & path** — per-host ping statistics with real jitter/loss/mdev/p95/p99, and a traceroute that never needs administrator rights. The first hop is diagnosed separately from the rest of the route, so loss or slowness there is correctly attributed to your own router/Wi-Fi rather than the ISP. Every hop is annotated with its ASN, AS name and country, and flags a route that detours through a third country on the way to the destination.
- **Bandwidth** — a cascading speedtest (Ookla binary → Cloudflare → fast.com → optional M-Lab NDT7) with separate download and upload bufferbloat grades, and a flag when the test server landed in a different country than you.
- **TLS handshake RTT** (`--tls`) — TCP RTT, TLS 1.3 handshake time and time-to-first-byte to reference services, flagging servers whose handshake is disproportionately slow relative to the network (CPU-bound TLS termination, not a network problem). Also captures each certificate's SHA-256 fingerprint, issuer and days until expiry, flags a validation failure, and checks against an optional pinned fingerprint (`tls.pinned_fingerprints` in `config.yaml`) to catch a corporate/ISP TLS-intercepting middlebox or a genuine MITM.
- **DNS: system vs DoH** (`--dns-advanced`) — compares your system resolver's answers and latency against Cloudflare/Google/Quad9 DoH, and probes a bogus resolver IP to detect a transparent DNS proxy intercepting port 53.
- **Path diversity / Anycast** (`--path-diversity`) — reads Cloudflare's `CF-RAY` edge code to find which PoP is actually serving your traffic, and flags an international routing loop when it's in a different country than you are.
- **AS prefix benchmark** (`--prefix-bench`) — pings the first host of a handful of your own AS's announced prefixes to find the lowest-latency PoP. Capped at 256 prefixes and off by default — this samples your own network, it does not scan it.
- **DPI / port self-check** (`--my-server <host>`) — a single-host TCP probe across 6 fixed ports on **a server you own**, classifying TCP RST injection vs silent filtering vs a clean response. Not a port scanner: one host per run, a fixed short port list, and it never reads its target from your own egress IP or from BGP data — see [ARCHITECTURE.md](ARCHITECTURE.md) for why.

## Handy things

| Flag | What it does |
|---|---|
| `--quick` | ~10 s express run: reference-host pings only, no speedtest |
| `--full` | ~60–120 s: full speedtest and full MTR cycles |
| `--target AS64500` / `--target 64500` / `--target 1.2.3.4` / `--target example.com` | Investigate a specific network instead of your own connection — the `AS` prefix on a bare ASN is optional |
| `--target-host <ip\|domain>` | Add an extra host to the ping and traceroute fan-out |
| `--speedtest-server <id\|url>` | Pin the speedtest to a specific server |
| `--watch` | Continuous monitoring with a live dashboard — for catching intermittent drops. Writes one `logs/watch_*.json` time series per session, not one report per tick |
| `--compare a.json b.json` | Diff two earlier reports: before/after a VPN switch, before/after an ISP call. Read-only — no probing, no network calls. Reads reports produced with `--format json` |
| `--trend N` | Sparkline trend across the last N saved JSON reports for this network. Read-only — resolves which network from the newest report already on disk, no probing needed |
| `--no-auto-diff` | Skip the one-line vs-previous-run summary a run otherwise prints automatically when it writes JSON and an earlier JSON report for the same network exists |
| `--dnsbl` | Opt in to classic DNSBL reputation zones |
| `--tls` | Measure TCP/TLS handshake RTT and TTFB to reference services. Included in `--full` |
| `--dns-advanced` | Compare system DNS vs DoH and probe for a transparent DNS proxy. Included in `--full` |
| `--path-diversity` | Compare client geo against the Cloudflare edge PoP actually serving traffic. Included in `--full` |
| `--prefix-bench` | Ping the first host of a handful of your own AS's announced prefixes to find the lowest-latency PoP. **Not** included in `--full` — opt in explicitly |
| `--my-server <host>` | Check a server **you own** for TCP port blocking / RST injection. Single host only — rejects CIDR input outright. **Not** included in `--full` — opt in explicitly |
| `--ndt7` | Opt in to M-Lab NDT7 (publishes your measurement, including your IP, as CC0 open data). On an interactive terminal it prints the consent notice and asks first; on a non-interactive one it proceeds without asking |
| `--tcp-trace` | Opt in to a scapy TCP-SYN traceroute through ICMP-filtering middleboxes (needs the `tcptrace` extra plus Npcap on Windows or root on Unix). Falls through to the normal cascade when it cannot run |
| `--format md,ru-md,json,prom,csv,all,none` | Choose which report artifacts to write (default: `md`). Repeatable and comma-separated (`--format md,json`); any use replaces the default instead of adding to it. `prom`/`csv` are metrics exports for scripting/monitoring — the same numbers as `json`, flattened. `all` writes every format, `none` writes nothing. Ignored with `--watch`/`--compare` |
| `--ru` | Shorthand for `--format ru-md` |
| `--json` | Shorthand for `--format json` |
| `--interface <name\|ip>` | Force outbound probing (identity, BGP/reputation, latency, traceroute, speedtest) through this adapter instead of the OS default route — e.g. compare a VPN adapter against your raw connection. Accepts an adapter name or one of its IPs. Errors out immediately, listing every adapter, if the name doesn't resolve or the adapter is down; if it resolves but has no route to the internet, the run continues and reports that honestly rather than aborting. Windows' `tracert` has no IPv4 source-address option, so that one traceroute tier is skipped when forced (noted in the report) — every other backend, including the Windows ICMP API, honors it |

Each run writes the selected artifacts into `./logs/`: an English Markdown report, a full Russian translation of the same report (`.ru.md`, same sections, same tables, same numbers — cross-linked with the English one when both are written), a JSON dump containing every raw provider response untruncated, and/or `.prom`/`.csv` metrics exports (the same numbers as the JSON dump, flattened for Prometheus/Grafana or a spreadsheet). Default is the English Markdown report only; set `output.formats` in `config.yaml` to change the default permanently, or pass `--format` per run. `./logs/` is gitignored — reports contain your external IP, city, coordinates and ISP name.

netsleuth never requires administrator or root. Where privileges would give better data, it degrades to an unprivileged method and says so in the report.

## For developers

Stack: Python 3.14+, Typer, Rich, httpx, pydantic-settings, dnspython, psutil, icmplib, ctypes.

```bash
uv sync --all-extras --group dev
uv run pytest -q
uv run netsleuth --quick
uv export --no-hashes --format requirements-txt -o requirements.txt   # after dependency changes
```

Architecture, data flow and the reasoning behind each provider choice: [ARCHITECTURE.md](ARCHITECTURE.md).

## Credits

netsleuth reads from RIPEstat, CAIDA ASRank, Team Cymru, PeeringDB, Cloudflare, ip-api.com, freeipapi.com, ipinfo.io, ipwho.is, Shodan InternetDB, the FireHOL blocklist project, Netflix fast.com and M-Lab. All of them are used within their free/keyless tiers.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — chosen because the default reputation sources (Shodan InternetDB, Spamhaus free mirrors) are non-commercial-use-only; this license keeps every downstream fork inside those same terms.
