# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Integration tests with `pytest-httpx` for mocking HTTP interactions
- Enum types for status, severity, and other string constants in models
- CI/CD publish job enabled with OIDC Trusted Publishing for PyPI

### Changed
- Extracted CLI utilities into `cli_commands` package for better modularity
- Replaced string constants with proper Enum types (`StatusEnum`, `SeverityEnum`, etc.)

### Fixed
- Enabled PyPI publication workflow (previously commented out)

## [0.1.0] - 2026-08-12

### Added
- Initial release of netsleuth
- Cross-platform network diagnostics CLI
- Identity detection (IPv4/IPv6, ASN, geo, organization)
- VPN/proxy assessment with weighted verdicts
- DNS leak testing per network adapter
- BGP intelligence (upstreams, peers, downstreams, IXP presence)
- Reputation checks (FireHOL, Shodan InternetDB, DNSBL)
- Latency and path analysis (ping, traceroute)
- Bandwidth testing with cascading speedtest
- TLS handshake RTT measurement
- DNS comparison (system vs DoH)
- Path diversity analysis via Cloudflare edge PoP
- AS prefix benchmarking
- DPI/port self-check for owned servers
- Continuous monitoring mode with live dashboard
- Report comparison for before/after analysis
- Multi-format output (Markdown English/Russian, JSON)
- Interface binding for VPN vs raw connection comparison
