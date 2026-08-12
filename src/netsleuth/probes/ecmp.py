from __future__ import annotations

from netsleuth.models import EcmpHop, EcmpReport, TraceHop, TraceResult


def detect_ecmp(runs: list[TraceResult]) -> EcmpReport:
    if not runs:
        return EcmpReport()
    target = runs[0].target
    by_ttl: dict[int, list[TraceHop]] = {}
    for trace in runs:
        for hop in trace.hops:
            if hop.ip:
                by_ttl.setdefault(hop.ttl, []).append(hop)

    hops: list[EcmpHop] = []
    divergent: list[int] = []
    for ttl in sorted(by_ttl):
        group = by_ttl[ttl]
        ips: list[str] = []
        avg_by_ip: dict[str, list[float]] = {}
        asns: list[str] = []
        for hop in group:
            if hop.ip not in ips:
                ips.append(hop.ip)
            if hop.avg_ms is not None:
                avg_by_ip.setdefault(hop.ip, []).append(hop.avg_ms)
            if hop.asn and hop.asn not in asns:
                asns.append(hop.asn)
        spread: float | None = None
        if len(ips) > 1:
            divergent.append(ttl)
            representative = [sum(v) / len(v) for v in avg_by_ip.values() if v]
            if len(representative) > 1:
                spread = round(max(representative) - min(representative), 3)
        hops.append(EcmpHop(ttl=ttl, ips=ips, asns=asns, rtt_spread_ms=spread))

    note = note_ru = ""
    if divergent:
        ttl_list = ", ".join(str(t) for t in divergent)
        note = f"Multiple next hops observed at TTL {ttl_list}."
        note_ru = f"На TTL {ttl_list} обнаружены разные следующие хопы."
    return EcmpReport(target=target, runs=len(runs), hops=hops, divergent_ttls=divergent, note=note, note_ru=note_ru)
