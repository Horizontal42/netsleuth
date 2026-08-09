from __future__ import annotations

from typing import Iterable

from netcheck.config import Band, BufferbloatBands, Thresholds, VpnBands
from netcheck.models import (
    CfTrace,
    DnsLeak,
    Finding,
    IpGeo,
    LocalNet,
    PingResult,
    Signal,
    SpeedResult,
    TraceResult,
    VpnAssessment,
)
from netcheck.netinfo import is_tunnel_iface, mtu_anomaly

_SEVERITY_ORDER = {"ok": 0, "info": 1, "warn": 2, "crit": 3}


def worst(severities: Iterable[str]) -> str:
    best = "ok"
    for severity in severities:
        if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[best]:
            best = severity
    return best


def severity_for(value: float | None, band: Band, higher_is_worse: bool = True) -> str:
    if value is None:
        return "info"
    if higher_is_worse:
        if value <= band.good:
            return "ok"
        return "warn" if value <= band.warn else "crit"
    if value >= band.good:
        return "ok"
    return "warn" if value >= band.warn else "crit"


def latency_findings(pings: list[PingResult], t: Thresholds) -> list[Finding]:
    findings: list[Finding] = []
    for p in pings:
        if p.received == 0:
            findings.append(
                Finding(
                    id=f"latency.unreachable.{p.label}",
                    severity="crit",
                    title=f"{p.host} did not answer",
                    detail=f"{p.sent} probes sent via {p.method}, none returned.",
                    metric="received",
                    value=0,
                    threshold=1,
                    advice="If every reference host is unreachable the link is down or filtering the probe method.",
                    title_ru=f"{p.host} не отвечает",
                    detail_ru=f"{p.sent} проб отправлено через {p.method}, ни одна не вернулась.",
                    advice_ru="Если все эталонные хосты недоступны, значит канал не работает или фильтрует метод пробы.",
                )
            )
            continue
        severity = severity_for(p.avg_ms, t.latency_ms)
        if severity not in ("ok", "info"):
            findings.append(
                Finding(
                    id=f"latency.avg.{p.label}",
                    severity=severity,
                    title=f"Latency to {p.host} above target",
                    detail=f"Average {p.avg_ms} ms over {p.received} probes via {p.method}.",
                    metric="avg_ms",
                    value=p.avg_ms,
                    threshold=t.latency_ms.warn,
                    advice="Check for a saturated uplink, a distant route, or a congested Wi-Fi link.",
                    title_ru=f"Задержка до {p.host} выше целевой",
                    detail_ru=f"Средняя {p.avg_ms} мс за {p.received} проб через {p.method}.",
                    advice_ru="Проверьте, не насыщен ли аплинк, не слишком ли далёкий маршрут или не перегружен ли Wi-Fi.",
                )
            )
        severity = severity_for(p.jitter_ms, t.jitter_ms)
        if severity not in ("ok", "info"):
            findings.append(
                Finding(
                    id=f"latency.jitter.{p.label}",
                    severity=severity,
                    title=f"Jitter to {p.host} above target",
                    detail=f"Jitter {p.jitter_ms} ms over {p.received} probes via {p.method}.",
                    metric="jitter_ms",
                    value=p.jitter_ms,
                    threshold=t.jitter_ms.warn,
                    advice="Unstable latency hurts calls and games more than raw latency does.",
                    title_ru=f"Джиттер до {p.host} выше целевого",
                    detail_ru=f"Джиттер {p.jitter_ms} мс за {p.received} проб через {p.method}.",
                    advice_ru="Нестабильная задержка вредит звонкам и играм сильнее, чем сама по себе высокая задержка.",
                )
            )
        severity = severity_for(p.loss_pct, t.loss_pct)
        if severity not in ("ok", "info"):
            kind = "connection failures" if p.method == "tcp" else "packet loss"
            kind_ru = "неудачных подключений" if p.method == "tcp" else "потерь пакетов"
            findings.append(
                Finding(
                    id=f"latency.loss.{p.label}",
                    severity=severity,
                    title=f"Loss to {p.host}",
                    detail=f"{p.loss_pct}% {kind} over {p.sent} probes via {p.method}.",
                    metric="loss_pct",
                    value=p.loss_pct,
                    threshold=t.loss_pct.warn,
                    advice="Sustained loss on every host points at the local link or the first upstream hop.",
                    title_ru=f"Потери до {p.host}",
                    detail_ru=f"{p.loss_pct}% {kind_ru} за {p.sent} проб через {p.method}.",
                    advice_ru="Устойчивые потери на всех хостах указывают на локальный канал или первый аплинк.",
                )
            )
    return findings


def path_findings(trace: TraceResult) -> list[Finding]:
    if not trace.hops:
        return [
            Finding(
                id="path.incomplete",
                severity="info",
                title="No path data",
                detail=f"The traceroute to {trace.target} returned no hops (backend {trace.backend}).",
                advice="ICMP may be filtered end to end; try --tcp-trace.",
                title_ru="Нет данных о маршруте",
                detail_ru=f"Трассировка до {trace.target} не вернула ни одного хопа (бэкенд {trace.backend}).",
                advice_ru="ICMP может быть отфильтрован на всём пути; попробуйте --tcp-trace.",
            )
        ]
    findings: list[Finding] = []
    for index, hop in enumerate(trace.hops[:-1]):
        following = trace.hops[index + 1]
        # A single lossy hop with clean hops after it is ICMP rate limiting on that
        # router, not a real problem; loss that persists to the next hop is real.
        if hop.loss_pct >= 20.0 and following.loss_pct >= 20.0:
            findings.append(
                Finding(
                    id="path.loss_jump",
                    severity="crit" if hop.loss_pct >= 50.0 else "warn",
                    title="Sustained loss starts mid-path",
                    detail=f"Loss appears at hop {hop.ttl} ({hop.ip or 'no reply'}) at {hop.loss_pct}% and persists downstream.",
                    metric="loss_pct",
                    value=hop.loss_pct,
                    threshold=20.0,
                    advice="This hop and everything after it share the problem; the hop before it is the last clean one.",
                    title_ru="Устойчивые потери начинаются в середине маршрута",
                    detail_ru=f"Потери появляются на хопе {hop.ttl} ({hop.ip or 'нет ответа'}) на уровне {hop.loss_pct}% и продолжаются дальше.",
                    advice_ru="Этот хоп и всё, что после него, делят одну проблему; хоп перед ним — последний чистый.",
                )
            )
            break
    if not trace.completed:
        findings.append(
            Finding(
                id="path.incomplete",
                severity="info",
                title="Path did not reach the target",
                detail=f"The trace to {trace.target} stopped at hop {trace.hops[-1].ttl}.",
                advice="Many networks drop the final ICMP reply; this alone is not a fault.",
                title_ru="Маршрут не достиг цели",
                detail_ru=f"Трассировка до {trace.target} остановилась на хопе {trace.hops[-1].ttl}.",
                advice_ru="Многие сети отбрасывают финальный ответ ICMP; само по себе это не является неисправностью.",
            )
        )
    return findings


SIGNAL_WEIGHTS: dict[str, float] = {
    "tunnel_iface": 0.35,
    "cf_warp": 0.50,
    "provider_proxy": 0.35,
    "provider_hosting": 0.40,
    "provider_mobile": 0.10,
    "mtu_anomaly": 0.20,
    "dns_asn_mismatch": 0.25,
    "gateway_egress_mismatch": 0.15,
    "pdb_info_type_nsp": 0.15,
    "timezone_mismatch": 0.15,
}

_TZ_COUNTRY_PREFIX = {
    "Europe/Amsterdam": "NL",
    "Europe/Moscow": "RU",
    "Europe/London": "GB",
    "Europe/Berlin": "DE",
    "America/New_York": "US",
    "America/Los_Angeles": "US",
    "Asia/Tokyo": "JP",
}


def _signal(name: str, observed: bool, note: str = "") -> Signal:
    return Signal(name=name, observed=observed, weight=SIGNAL_WEIGHTS[name], direction="vpn", note=note)


def gather_vpn_signals(
    local: LocalNet,
    geo: IpGeo,
    cf: CfTrace | None,
    dns_leak: DnsLeak | None,
    pdb_info_type: str | None,
    os_timezone: str | None,
    provider_flags: dict[str, bool],
) -> list[Signal]:
    iface = local.iface_name or ""
    anomaly = mtu_anomaly(local.iface_mtu)
    leaking = [
        a
        for a in (dns_leak.per_adapter if dns_leak else [])
        if a.matches_egress_asn is False
    ]
    tz_country = _TZ_COUNTRY_PREFIX.get(os_timezone or "")
    return [
        _signal("tunnel_iface", is_tunnel_iface(iface), iface),
        _signal("cf_warp", bool(cf and (cf.warp or "").lower() == "on"), (cf.warp if cf else "") or ""),
        _signal("provider_proxy", bool(provider_flags.get("proxy"))),
        _signal("provider_hosting", bool(provider_flags.get("hosting"))),
        _signal("provider_mobile", bool(provider_flags.get("mobile"))),
        _signal("mtu_anomaly", anomaly in ("wireguard", "ipsec"), anomaly or ""),
        _signal(
            "dns_asn_mismatch",
            bool(leaking),
            ", ".join(f"{a.adapter} -> {a.echoed_asn}" for a in leaking),
        ),
        _signal(
            "gateway_egress_mismatch",
            bool(local.default_gateway_v4 and is_tunnel_iface(iface)),
            local.default_gateway_v4 or "",
        ),
        _signal("pdb_info_type_nsp", (pdb_info_type or "").upper() in ("NSP", "CONTENT", "ENTERPRISE"), pdb_info_type or ""),
        _signal(
            "timezone_mismatch",
            bool(tz_country and geo.country_code and tz_country != geo.country_code),
            f"{os_timezone} vs {geo.country_code}" if tz_country else "",
        ),
    ]


def score_vpn(signals: list[Signal], bands: VpnBands) -> tuple[str, float]:
    total = 0.0
    for s in signals:
        if not s.observed:
            continue
        total += s.weight if s.direction == "vpn" else -s.weight
    confidence = round(max(0.0, min(1.0, total)), 3)
    if confidence >= bands.confirmed:
        return "confirmed", confidence
    if confidence >= bands.likely:
        return "likely", confidence
    return "none", confidence


def assess_vpn(
    signals: list[Signal],
    bands: VpnBands,
    tunnel_iface: str | None,
    dns_leak: DnsLeak | None,
) -> VpnAssessment:
    verdict, confidence = score_vpn(signals, bands)
    return VpnAssessment(
        verdict=verdict,
        confidence=confidence,
        signals=signals,
        tunnel_iface=tunnel_iface,
        dns_leak=dns_leak,
    )


_CONSEQUENCES = {
    "A": "Video calls and games stay smooth while the line is fully loaded.",
    "B": "Barely noticeable; a large upload may add a beat to a video call.",
    "C": "Calls and games get choppy whenever something else is downloading.",
    "D": "Any big transfer makes calls stutter and pages feel stuck.",
    "E": "The connection feels broken while it is busy, even though bandwidth is fine.",
    "F": "A single download makes a call unusable; this is queue bloat, not a slow line.",
    "?": "Not measured — the speedtest tier that measures it did not run.",
}
_CONSEQUENCES_RU = {
    "A": "Видеозвонки и игры остаются плавными, даже когда канал полностью загружен.",
    "B": "Почти незаметно; большая отдача может слегка споткнуть видеозвонок.",
    "C": "Звонки и игры начинают дёргаться, как только что-то ещё скачивается.",
    "D": "Любая крупная передача заставляет звонки заикаться, а страницы — зависать.",
    "E": "Соединение кажется сломанным, пока оно занято, хотя пропускная способность в порядке.",
    "F": "Одна закачка делает звонок непригодным; это раздутие очереди, а не медленный канал.",
    "?": "Не измерено — уровень speedtest-каскада, который это измеряет, не запускался.",
}
_GRADE_SEVERITY = {"A": "ok", "B": "ok", "C": "warn", "D": "crit", "E": "crit", "F": "crit", "?": "info"}


def grade_bufferbloat(delta_ms: float | None, bands: BufferbloatBands) -> str:
    if delta_ms is None:
        return "?"
    delta = max(0.0, delta_ms)
    for grade, ceiling in (("A", bands.a), ("B", bands.b), ("C", bands.c), ("D", bands.d), ("E", bands.e)):
        if delta <= ceiling:
            return grade
    return "F"


def bufferbloat_consequence(grade: str, lang: str = "en") -> str:
    table = _CONSEQUENCES_RU if lang == "ru" else _CONSEQUENCES
    return table.get(grade, table["?"])


def speed_findings(speed: SpeedResult, bands: BufferbloatBands) -> list[Finding]:
    if speed.method == "none":
        tried = ", ".join(a.tier for a in speed.tier_attempts) or "none"
        return [
            Finding(
                id="speed.unavailable",
                severity="info",
                title="No bandwidth measurement",
                detail=f"Every speedtest tier failed or was disabled (tried: {tried}).",
                advice="Install the Ookla speedtest binary, or rerun without --quick.",
                title_ru="Нет замера скорости",
                detail_ru=f"Все уровни speedtest-каскада завершились неудачей или были отключены (пробовали: {tried}).",
                advice_ru="Установите бинарник Ookla speedtest или перезапустите без --quick.",
            )
        ]
    findings: list[Finding] = []
    for direction, direction_ru, delta in (
        ("down", "приём", speed.bufferbloat_down_ms),
        ("up", "передача", speed.bufferbloat_up_ms),
    ):
        grade = grade_bufferbloat(delta, bands)
        severity = _GRADE_SEVERITY[grade]
        if severity in ("ok", "info"):
            continue
        findings.append(
            Finding(
                id=f"speed.bufferbloat_{direction}",
                severity=severity,
                title=f"Bufferbloat under load ({direction}stream): grade {grade}",
                detail=f"Latency rose by {delta} ms while saturating the {direction}stream direction.",
                metric=f"bufferbloat_{direction}_ms",
                value=grade,
                threshold=bands.c,
                advice=bufferbloat_consequence(grade)
                + " Enabling SQM/fq_codel on the router is the standard fix.",
                title_ru=f"Bufferbloat под нагрузкой ({direction_ru}): оценка {grade}",
                detail_ru=f"Задержка выросла на {delta} мс при насыщении канала на {direction_ru}.",
                advice_ru=bufferbloat_consequence(grade, lang="ru")
                + " Включение SQM/fq_codel на роутере — стандартное решение.",
            )
        )
    return findings


_SCORE_PENALTY = {"ok": 0, "info": 3, "warn": 10, "crit": 25}


def overall_verdict(findings: list[Finding]) -> tuple[str, int, str]:
    score = 100
    for f in findings:
        score -= _SCORE_PENALTY[f.severity]
    score = max(0, score)
    status = worst(f.severity for f in findings)
    if status in ("ok", "info"):
        return "ok", score, "No problems found on this connection."
    headline = [f.title for f in findings if f.severity == status]
    return status, score, "; ".join(headline[:3])
