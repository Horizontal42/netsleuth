from __future__ import annotations

import re

from netsleuth.models import TraceConfig, TraceHop, TraceResult
from netsleuth.stats import rtt_stats

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
ANNOTATION_RE = re.compile(r"!\w*")
_HOP_LINE_RE = re.compile(r"^\s*(\d{1,3})\s+(.*)$")
_UNIX_PROBE_RE = re.compile(r"(?P<rtt>\d+(?:\.\d+)?)\s*ms|(?P<star>\*)")
_UNIX_HOSTIP_RE = re.compile(r"(?P<name>[A-Za-z0-9._-]+)\s+\((?P<ip>[0-9a-fA-F:.]+)\)")


def finalize_hop(hop: TraceHop) -> TraceHop:
    """Compute RTT statistics for a traceroute hop from its probe samples.

    Updates the hop's loss_pct, min_ms, avg_ms, max_ms, and jitter_ms fields
    based on the raw probe measurements in hop.probes.

    Args:
        hop: A TraceHop with raw probe data in the probes list.

    Returns:
        The same TraceHop object with computed statistics populated.
    """
    s = rtt_stats(hop.probes)
    hop.loss_pct = s.loss_pct
    hop.min_ms = s.min_ms
    hop.avg_ms = s.avg_ms
    hop.max_ms = s.max_ms
    hop.jitter_ms = s.jitter_ms
    return hop


def _extract_ip(text: str) -> str | None:
    """Extract the first IPv4 or IPv6 address from a string.

    Searches for an IPv4 address first, then falls back to IPv6.

    Args:
        text: String potentially containing an IP address.

    Returns:
        The first IP address found (IPv4 preferred), or None if no match.
    """
    v4 = IPV4_RE.search(text)
    if v4:
        return v4.group(0)
    v6 = IPV6_RE.search(text)
    return v6.group(0) if v6 else None


def _unix_host_and_ip(body: str) -> tuple[str | None, str | None]:
    """Extract hostname and IP address from a Unix traceroute hop line.

    Parses output like 'hostname (192.168.1.1)' or just an IP address,
    returning the hostname only if it differs from the IP.

    Args:
        body: The text portion of a traceroute hop line after the TTL number.

    Returns:
        A tuple of (hostname_or_None, ip_address_or_None).
        Hostname is None if it matches the IP or isn't present.
    """
    match = _UNIX_HOSTIP_RE.search(body)
    if match:
        name, ip = match.group("name"), match.group("ip")
        return (None if name == ip else name), ip
    return None, _extract_ip(body)


def _unix_probes(body: str) -> list[float | None]:
    """Extract RTT probe values from a Unix traceroute hop line.

    Parses measurements like '1.234 ms' or '*' (timeout) from the hop body.

    Args:
        body: The text portion of a traceroute hop line containing probe results.

    Returns:
        A list of float RTT values in milliseconds, with None for timeouts (*).
    """
    return [
        None if match.group("star") else float(match.group("rtt"))
        for match in _UNIX_PROBE_RE.finditer(body)
    ]


def _unix_annotations(body: str) -> list[str]:
    """Extract annotation markers from a Unix traceroute hop line.

    Annotations are special codes like '!H' (host unreachable) or '!N'
    (network unreachable) that appear in traceroute output.

    Args:
        body: The text portion of a traceroute hop line.

    Returns:
        A deduplicated list of annotation markers found in the body.
    """
    return list(dict.fromkeys(ANNOTATION_RE.findall(body)))


def parse_linux(text: str) -> list[TraceHop]:
    """Parse Linux traceroute output into structured hop data.

    Processes GNU-style traceroute output, extracting TTL, IP addresses,
    reverse DNS, RTT probes, and annotations for each hop.

    Args:
        text: Raw output from a Linux/GNU traceroute command.

    Returns:
        A list of TraceHop objects, one per hop found in the output.
    """
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


# tracert reports any sub-millisecond RTT as "<1 ms"; the midpoint of (0, 1) is
# the least-wrong single value to record for it.
WINDOWS_SUB_MS = 0.5

_WIN_PROBE_RE = re.compile(r"(?P<lt><)?\s*(?P<rtt>\d+)\s*ms|(?P<star>\*)")
_WIN_BRACKET_RE = re.compile(r"\[(?P<ip>[0-9a-fA-F:.%]+)\]")
_WIN_NAME_RE = re.compile(r"(?P<name>[A-Za-z0-9._-]+)\s*\[")


def parse_windows(text: str) -> list[TraceHop]:
    """Parse Windows tracert output into structured hop data.

    Handles Windows-specific formatting including '<1 ms' notation, bracketed
    IP addresses, and localized output variations.

    Args:
        text: Raw output from a Windows tracert command.

    Returns:
        A list of TraceHop objects, one per hop found in the output.
    """
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


_BSD_CONTINUATION_RE = re.compile(r"^\s+\S")


def parse_darwin(text: str) -> list[TraceHop]:
    """Parse macOS/BSD traceroute output into structured hop data.

    Handles BSD-style traceroute output, which differs from GNU traceroute by
    printing continuation lines for multipath routes where probes return from
    different routers at the same TTL.

    Args:
        text: Raw output from a macOS/BSD traceroute command.

    Returns:
        A list of TraceHop objects, one per hop found in the output.
        Multipath hops are merged with alternate IPs recorded as annotations.
    """
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


def parse_traceroute(text: str, os_name: str) -> list[TraceHop]:
    """Dispatch traceroute output parsing based on the operating system.

    Routes raw traceroute output to the appropriate parser (Windows, macOS/BSD,
    or Linux/GNU) based on the OS name.

    Args:
        text: Raw output from a traceroute command.
        os_name: The operating system name ('Windows', 'Darwin', or other).

    Returns:
        A list of TraceHop objects parsed using the OS-specific parser.
        Falls back to the Linux parser for unknown OS names.
    """
    if os_name == "Windows":
        return parse_windows(text)
    if os_name == "Darwin":
        return parse_darwin(text)
    return parse_linux(text)


def build_trace_result(
    text: str,
    os_name: str,
    config: TraceConfig,
) -> TraceResult:
    hops = parse_traceroute(text, os_name)
    completed = bool(hops and config.resolved_ip and hops[-1].ip == config.resolved_ip)
    max_hops_reached = bool(hops) and not completed and hops[-1].ttl >= config.max_hops
    return TraceResult(
        target=config.target,
        resolved_ip=config.resolved_ip,
        backend=config.backend,
        hops=hops,
        cycles=1,
        completed=completed,
        max_hops_reached=max_hops_reached,
    )
