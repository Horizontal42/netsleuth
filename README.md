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
