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
    s = rtt_stats(hop.probes)
    hop.loss_pct = s.loss_pct
    hop.min_ms = s.min_ms
    hop.avg_ms = s.avg_ms
    hop.max_ms = s.max_ms
    hop.jitter_ms = s.jitter_ms
    return hop


def _extract_ip(text: str) -> str | None:
    v4 = IPV4_RE.search(text)
    if v4:
        return v4.group(0)
    v6 = IPV6_RE.search(text)
    return v6.group(0) if v6 else None


def _unix_host_and_ip(body: str) -> tuple[str | None, str | None]:
    match = _UNIX_HOSTIP_RE.search(body)
    if match:
        name, ip = match.group("name"), match.group("ip")
        return (None if name == ip else name), ip
    return None, _extract_ip(body)


def _unix_probes(body: str) -> list[float | None]:
    probes: list[float | None] = []
    for match in _UNIX_PROBE_RE.finditer(body):
        probes.append(None if match.group("star") else float(match.group("rtt")))
    return probes


def _unix_annotations(body: str) -> list[str]:
    return list(dict.fromkeys(ANNOTATION_RE.findall(body)))


def parse_linux(text: str) -> list[TraceHop]:
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
