from __future__ import annotations


from netsleuth.config import Band, BufferbloatBands, Thresholds, VpnBands
from netsleuth.models import (
    CaptivePortal,
    CfTrace,
    DnsAdvanced,
    DnsLeak,
    DpiCheckResult,
    Finding,
    IpGeo,
    LocalNet,
    PathDiversity,
    PingResult,
    PrefixBenchmark,
    Signal,
    SpeedResult,
    TlsResult,
    TraceHop,
    TraceResult,
    VpnAssessment,
    VpnContext,
)
from netsleuth.netinfo import is_cgnat, is_tunnel_iface, mtu_anomaly

_SEVERITY_ORDER = {"ok": 0, "info": 1, "warn": 2, "crit": 3}


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


def _first_hop_findings(hop: TraceHop, local: LocalNet, t: Thresholds) -> list[Finding]:
    if not hop.ip:
        return []
    is_gateway = bool(local.default_gateway_v4) and hop.ip == local.default_gateway_v4
    findings: list[Finding] = []
    where = f"your LAN/Wi-Fi link to {hop.ip}" if is_gateway else f"the first hop ({hop.ip})"
    where_ru = f"вашу локальную сеть/Wi-Fi до {hop.ip}" if is_gateway else f"первый хоп ({hop.ip})"
    if hop.loss_pct >= 20.0 or hop.loss_pct > t.loss_pct.warn:
        severity = "crit" if hop.loss_pct >= 20.0 else "warn"
        findings.append(
            Finding(
                id="path.first_hop_loss",
                severity=severity,
                title="Loss starts at the first hop",
                detail=f"{hop.loss_pct}% loss to {where}, before the rest of the path is even reached.",
                metric="loss_pct",
                value=hop.loss_pct,
                threshold=20.0,
                advice="This points at your own router or Wi-Fi link, not your ISP or anything further downstream.",
                title_ru="Потери начинаются на первом хопе",
                detail_ru=f"{hop.loss_pct}% потерь до {where_ru}, ещё до остального маршрута.",
                advice_ru="Это указывает на ваш собственный роутер или Wi-Fi-канал, а не на провайдера или что-то дальше по маршруту.",
            )
        )
    severity = severity_for(hop.avg_ms, t.first_hop_ms)
    if severity not in ("ok", "info"):
        findings.append(
            Finding(
                id="path.first_hop_slow",
                severity=severity,
                title="First hop is slow",
                detail=f"{hop.avg_ms} ms to {where}.",
                metric="avg_ms",
                value=hop.avg_ms,
                threshold=t.first_hop_ms.warn,
                advice="A slow first hop is almost always local: a congested Wi-Fi link or an overloaded router.",
                title_ru="Первый хоп медленный",
                detail_ru=f"{hop.avg_ms} мс до {where_ru}.",
                advice_ru="Медленный первый хоп почти всегда локальная проблема: перегруженный Wi-Fi или роутер.",
            )
        )
    if local.default_gateway_v4 and not is_gateway:
        findings.append(
            Finding(
                id="path.first_hop_unexpected",
                severity="info",
                title="First hop is not your default gateway",
                detail=f"Traceroute's first hop is {hop.ip}, but the OS default gateway is {local.default_gateway_v4}.",
                advice="A double NAT, a bridged modem, or a VPN intercepting traffic before it reaches the real gateway can cause this.",
                title_ru="Первый хоп — не ваш шлюз по умолчанию",
                detail_ru=f"Первый хоп трассировки — {hop.ip}, а шлюз ОС по умолчанию — {local.default_gateway_v4}.",
                advice_ru="Причиной может быть двойной NAT, модем в режиме моста, либо VPN, перехватывающий трафик до настоящего шлюза.",
            )
        )
    return findings


def path_findings(trace: TraceResult, local: LocalNet | None = None, t: Thresholds | None = None) -> list[Finding]:
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
    if local is not None:
        findings += _first_hop_findings(trace.hops[0], local, t or Thresholds())
    # A run of lossy hops that clears before the last hop we have data for is ICMP
    # rate limiting on those routers, not a real problem, no matter how many hops
    # in a row stayed silent; only loss that persists all the way to the end is real.
    loss_persists_to_the_end = trace.hops[-1].loss_pct >= 20.0
    for hop, following in zip(trace.hops, trace.hops[1:]):
        if loss_persists_to_the_end and hop.loss_pct >= 20.0 and following.loss_pct >= 20.0:
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


def captive_portal_findings(cp: CaptivePortal) -> list[Finding]:
    if cp.detected:
        return [
            Finding(
                id="net.captive_portal",
                severity="crit",
                title="Behind a captive portal",
                detail=cp.note,
                metric="portal_url",
                value=cp.portal_url,
                advice="Every measurement below was taken from behind the portal. Sign in through a browser, then rerun.",
                title_ru="За captive portal",
                detail_ru=cp.note_ru or cp.note,
                advice_ru="Все измерения ниже сделаны из-за captive portal. Авторизуйтесь через браузер и перезапустите.",
            )
        ]
    if cp.verdict == "suspect":
        return [
            Finding(
                id="net.captive_portal_suspect",
                severity="warn",
                title="Captive portal check was inconclusive",
                detail=cp.note,
                advice="No check returned a clean expected response, but none looked like a portal redirect either; treat other findings with a grain of salt.",
                title_ru="Проверка captive portal неоднозначна",
                detail_ru=cp.note_ru or cp.note,
                advice_ru="Ни одна проверка не вернула чистый ожидаемый ответ, но и на редирект портала не похоже; к остальным находкам стоит относиться с осторожностью.",
            )
        ]
    return []


def cgnat_findings(local: LocalNet, traces: list[TraceResult]) -> list[Finding]:
    evidence = local.cgnat_evidence
    detected = local.cgnat
    if not detected:
        for trace in traces:
            for hop in trace.hops:
                if is_cgnat(hop.ip):
                    detected = True
                    evidence = f"traceroute hop {hop.ttl} ({hop.ip}) is in 100.64.0.0/10"
                    break
            if detected:
                break
    if not detected:
        return []
    return [
        Finding(
            id="net.cgnat",
            severity="warn",
            title="Behind carrier-grade NAT (CGNAT)",
            detail=evidence or "An address in 100.64.0.0/10 (RFC 6598) was observed.",
            metric="cgnat",
            value=True,
            advice="No inbound port forwarding is possible; P2P and game/server hosting may not work. "
            "Ask your ISP for a public IPv4 address, or use IPv6 where the destination supports it.",
            title_ru="За carrier-grade NAT (CGNAT)",
            detail_ru=evidence or "Обнаружен адрес из диапазона 100.64.0.0/10 (RFC 6598).",
            advice_ru="Проброс входящих портов невозможен; P2P и хостинг игр/серверов могут не работать. "
            "Запросите у провайдера публичный IPv4-адрес либо используйте IPv6, если целевой сервис его поддерживает.",
        )
    ]


def dual_stack_findings(nat64_prefix: str | None, local: LocalNet) -> list[Finding]:
    if not nat64_prefix:
        return []
    severity = "warn" if not local.is_dual_stack else "info"
    return [
        Finding(
            id="net.nat64",
            severity=severity,
            title="IPv6 traffic is translated via NAT64",
            detail=f"ipv4only.arpa resolved through a NAT64 synthesis prefix ({nat64_prefix}).",
            metric="nat64_prefix",
            value=nat64_prefix,
            advice="This network is IPv6-only with 464XLAT/NAT64 translation to reach IPv4-only destinations; "
            "this can add latency and occasionally breaks apps that assume native IPv4."
            if not local.is_dual_stack
            else "IPv4-only destinations are reached via NAT64 translation even though this host is dual-stack.",
            title_ru="IPv6-трафик транслируется через NAT64",
            detail_ru=f"ipv4only.arpa разрешился через префикс синтеза NAT64 ({nat64_prefix}).",
            advice_ru="Сеть IPv6-only с трансляцией 464XLAT/NAT64 для доступа к IPv4-only ресурсам; "
            "это может добавлять задержку и иногда ломает приложения, рассчитывающие на нативный IPv4."
            if not local.is_dual_stack
            else "IPv4-only ресурсы доступны через трансляцию NAT64, хотя хост dual-stack.",
        )
    ]


def path_asn_findings(trace: TraceResult, client_country: str | None) -> list[Finding]:
    if not client_country or len(trace.hops) < 2:
        return []
    final_country = trace.hops[-1].country
    run: list[TraceHop] = []
    for hop in trace.hops:
        detour = bool(hop.country) and hop.country != client_country and hop.country != final_country
        if not detour:
            run = []
            continue
        run.append(hop)
        if len(run) < 2:
            continue
        countries = ", ".join(dict.fromkeys(h.country for h in run if h.country))
        first, last = run[0], run[-1]
        return [
            Finding(
                id="path.detour_country",
                severity="info",
                title=f"Route to {trace.target} detours through {countries}",
                detail=f"Hops {first.ttl}-{last.ttl} are in {countries}, neither your country ({client_country}) nor the destination's.",
                metric="detour_countries",
                value=countries,
                advice="Not necessarily a problem, but it explains extra latency if the detour is geographically far.",
                title_ru=f"Маршрут до {trace.target} идёт через {countries}",
                detail_ru=f"Хопы {first.ttl}-{last.ttl} находятся в {countries} — не в вашей стране ({client_country}) и не в стране назначения.",
                advice_ru="Не обязательно проблема, но объясняет дополнительную задержку, если крюк географически большой.",
            )
        ]
    return []


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


def gather_vpn_signals(ctx: VpnContext) -> list[Signal]:
    iface = ctx.local.iface_name or ""
    anomaly = mtu_anomaly(ctx.local.iface_mtu)
    leaking = [
        a
        for a in (ctx.dns_leak.per_adapter if ctx.dns_leak else [])
        if a.matches_egress_asn is False
    ]
    tz_country = _TZ_COUNTRY_PREFIX.get(ctx.os_timezone or "")
    return [
        _signal("tunnel_iface", is_tunnel_iface(iface), iface),
        _signal("cf_warp", bool(ctx.cf and (ctx.cf.warp or "").lower() == "on"), (ctx.cf.warp if ctx.cf else "") or ""),
        _signal("provider_proxy", bool(ctx.provider_flags.get("proxy"))),
        _signal("provider_hosting", bool(ctx.provider_flags.get("hosting"))),
        _signal("provider_mobile", bool(ctx.provider_flags.get("mobile"))),
        _signal("mtu_anomaly", anomaly in ("wireguard", "ipsec"), anomaly or ""),
        _signal(
            "dns_asn_mismatch",
            bool(leaking),
            ", ".join(f"{a.adapter} -> {a.echoed_asn}" for a in leaking),
        ),
        _signal(
            "gateway_egress_mismatch",
            bool(ctx.local.default_gateway_v4 and is_tunnel_iface(iface)),
            ctx.local.default_gateway_v4 or "",
        ),
        _signal("pdb_info_type_nsp", (ctx.pdb_info_type or "").upper() in ("NSP", "CONTENT", "ENTERPRISE"), ctx.pdb_info_type or ""),
        _signal(
            "timezone_mismatch",
            bool(tz_country and ctx.geo.country_code and tz_country != ctx.geo.country_code),
            f"{ctx.os_timezone} vs {ctx.geo.country_code}" if tz_country else "",
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


def speed_findings(speed: SpeedResult, bands: BufferbloatBands, client_country: str | None = None) -> list[Finding]:
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
    if client_country and speed.server_country and client_country.casefold() != speed.server_country.casefold():
        findings.append(
            Finding(
                id="speed.server_other_country",
                severity="info",
                title="Speedtest server is in another country",
                detail=f"The speedtest server is in {speed.server_country}, you are in {client_country}.",
                metric="server_country",
                value=speed.server_country,
                advice="A distant server can understate real throughput and overstate latency; "
                "pin a closer one with --speedtest-server if one exists.",
                title_ru="Сервер speedtest в другой стране",
                detail_ru=f"Сервер speedtest находится в {speed.server_country}, а вы — в {client_country}.",
                advice_ru="Далёкий сервер может занижать реальную пропускную способность и завышать задержку; "
                "закрепите более близкий через --speedtest-server, если такой есть.",
            )
        )
    return findings


def _cpu_bound_ratio(tls_handshake_ms: float | None, tcp_rtt_ms: float | None) -> float | None:
    if tls_handshake_ms is None or not tcp_rtt_ms:
        return None
    return tls_handshake_ms / tcp_rtt_ms


def tls_findings(results: list[TlsResult], t: Thresholds) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        if r.error:
            findings.append(
                Finding(
                    id=f"tls.unreachable.{r.label}",
                    severity="warn",
                    title=f"TLS handshake to {r.host} failed",
                    detail=f"Could not complete a TLS connection to {r.host}:{r.port}: {r.error}",
                    metric="error",
                    value=r.error,
                    advice="The service may be down, or the port may be blocked between here and the server.",
                    title_ru=f"TLS-рукопожатие с {r.host} не удалось",
                    detail_ru=f"Не удалось установить TLS-соединение с {r.host}:{r.port}: {r.error}",
                    advice_ru="Сервис может быть недоступен, либо порт заблокирован на пути к серверу.",
                )
            )
            continue
        ratio = _cpu_bound_ratio(r.tls_handshake_ms, r.tcp_rtt_ms)
        if ratio is not None and ratio > t.tls_cpu_bound_ratio and (r.tls_handshake_ms or 0.0) >= 20.0:
            findings.append(
                Finding(
                    id=f"tls.server_cpu_bound.{r.label}",
                    severity="warn",
                    title=f"TLS handshake to {r.host} is disproportionately slow",
                    detail=f"TLS handshake took {r.tls_handshake_ms} ms, {ratio:.1f}x the {r.tcp_rtt_ms} ms TCP RTT.",
                    metric="tls_handshake_ms",
                    value=r.tls_handshake_ms,
                    threshold=t.tls_cpu_bound_ratio,
                    advice="Slow handshake relative to network RTT usually points at a CPU-bound TLS terminator, not the network.",
                    title_ru=f"TLS-рукопожатие с {r.host} непропорционально медленное",
                    detail_ru=f"TLS-рукопожатие заняло {r.tls_handshake_ms} мс — в {ratio:.1f} раза больше TCP RTT ({r.tcp_rtt_ms} мс).",
                    advice_ru="Медленное рукопожатие относительно сетевого RTT обычно указывает на упирающийся в CPU TLS-терминатор, а не на сеть.",
                )
            )
        severity = severity_for(r.tls_handshake_ms, t.tls_handshake_ms)
        if severity not in ("ok", "info"):
            findings.append(
                Finding(
                    id=f"tls.handshake_slow.{r.label}",
                    severity=severity,
                    title=f"TLS handshake to {r.host} above target",
                    detail=f"TLS handshake took {r.tls_handshake_ms} ms.",
                    metric="tls_handshake_ms",
                    value=r.tls_handshake_ms,
                    threshold=t.tls_handshake_ms.warn,
                    advice="Check server load and TLS session resumption settings.",
                    title_ru=f"TLS-рукопожатие с {r.host} выше целевого",
                    detail_ru=f"TLS-рукопожатие заняло {r.tls_handshake_ms} мс.",
                    advice_ru="Проверьте нагрузку на сервер и настройки возобновления TLS-сессий.",
                )
            )
        severity = severity_for(r.ttfb_ms, t.ttfb_ms)
        if severity not in ("ok", "info"):
            findings.append(
                Finding(
                    id=f"tls.ttfb_slow.{r.label}",
                    severity=severity,
                    title=f"Time to first byte from {r.host} above target",
                    detail=f"TTFB was {r.ttfb_ms} ms.",
                    metric="ttfb_ms",
                    value=r.ttfb_ms,
                    threshold=t.ttfb_ms.warn,
                    advice="Slow TTFB with a fast handshake points at server-side processing, not the network.",
                    title_ru=f"Время до первого байта от {r.host} выше целевого",
                    detail_ru=f"TTFB составило {r.ttfb_ms} мс.",
                    advice_ru="Медленный TTFB при быстром рукопожатии указывает на обработку на стороне сервера, а не на сеть.",
                )
            )
    return findings


def prefix_findings(bench: PrefixBenchmark, t: Thresholds) -> list[Finding]:
    findings: list[Finding] = []
    if not bench.results:
        return findings
    severity = severity_for(bench.spread_ms, t.prefix_spread_ms)
    if severity not in ("ok", "info"):
        findings.append(
            Finding(
                id="prefix.spread",
                severity=severity,
                title="Latency spread across AS prefixes is high",
                detail=f"Spread between best ({bench.best}) and worst ({bench.worst}) probed prefix is {bench.spread_ms} ms.",
                metric="spread_ms",
                value=bench.spread_ms,
                threshold=t.prefix_spread_ms.warn,
                advice="Pick the best-performing prefix's PoP as your entry point if your provider lets you choose.",
                title_ru="Разброс задержки между префиксами AS велик",
                detail_ru=f"Разброс между лучшим ({bench.best}) и худшим ({bench.worst}) префиксом составляет {bench.spread_ms} мс.",
                advice_ru="Если провайдер позволяет выбрать точку входа, выбирайте PoP с лучшим префиксом.",
            )
        )
    unreachable = sum(1 for p in bench.results if not p.reachable)
    if unreachable / len(bench.results) > 0.7:
        reachable_pct = round(100 * (1 - unreachable / len(bench.results)), 1)
        findings.append(
            Finding(
                id="prefix.mostly_unreachable",
                severity="info",
                title="Most probed prefixes did not answer",
                detail=f"{unreachable} of {len(bench.results)} probed prefixes gave no ICMP reply.",
                metric="reachable_pct",
                value=reachable_pct,
                advice="Many networks filter ICMP to the first host of a subnet; this is common and not necessarily a fault.",
                title_ru="Большинство проверенных префиксов не ответили",
                detail_ru=f"{unreachable} из {len(bench.results)} проверенных префиксов не дали ответа по ICMP.",
                advice_ru="Многие сети фильтруют ICMP к первому хосту подсети; это обычное явление, не обязательно неисправность.",
            )
        )
    return findings


_DPI_TEXT = {
    "reset_injection": ("crit", "Possible active DPI interference on {t}", "Возможное активное вмешательство DPI на {t}"),
    "partial_filtering": ("warn", "Selective port filtering detected on {t}", "Обнаружена выборочная фильтрация портов на {t}"),
    "unreachable": ("info", "{t} did not respond on any probed port", "{t} не ответил ни на одном проверенном порту"),
}


def dpi_findings(result: DpiCheckResult) -> list[Finding]:
    spec = _DPI_TEXT.get(result.verdict)
    if spec is None:
        return []
    severity, title, title_ru = spec
    title = title.format(t=result.target)
    title_ru = title_ru.format(t=result.target)
    return [
        Finding(
            id=f"dpi.{result.verdict}",
            severity=severity,
            title=title,
            detail=result.rationale,
            metric="verdict",
            value=result.verdict,
            advice="Try the same ports over a VPN/proxy to confirm whether the block is on the path to this specific server.",
            title_ru=title_ru,
            detail_ru=result.rationale_ru or "",
            advice_ru="Попробуйте те же порты через VPN/прокси, чтобы подтвердить, что блокировка именно на пути к этому серверу.",
        )
    ]


def dns_advanced_findings(adv: DnsAdvanced, t: Thresholds) -> list[Finding]:
    findings: list[Finding] = []
    if adv.transparent_proxy is True:
        findings.append(
            Finding(
                id="dns.transparent_proxy",
                severity="warn",
                title="ISP appears to intercept DNS traffic on port 53",
                detail=adv.transparent_proxy_detail or "",
                advice="A transparent DNS proxy can silently redirect or rewrite lookups even when you configure a different resolver.",
                title_ru="Провайдер, похоже, перехватывает DNS-трафик на 53 порту",
                detail_ru=adv.transparent_proxy_detail or "",
                advice_ru="Прозрачный DNS-прокси может незаметно перенаправлять или подменять запросы, даже если вы указали другой резолвер.",
            )
        )
    if adv.system_avg_ms is not None and adv.doh_avg_ms is not None:
        severity = severity_for(adv.system_avg_ms, t.dns_resolve_ms)
        if severity not in ("ok", "info") and adv.system_avg_ms > adv.doh_avg_ms:
            findings.append(
                Finding(
                    id="dns.system_slow",
                    severity=severity,
                    title="System DNS resolver is slow compared to DoH",
                    detail=f"System resolver averaged {adv.system_avg_ms} ms vs {adv.doh_avg_ms} ms over DoH.",
                    metric="system_avg_ms",
                    value=adv.system_avg_ms,
                    threshold=t.dns_resolve_ms.warn,
                    advice="Switching the OS resolver to a faster public one (or using DoH) may cut page load latency.",
                    title_ru="Системный DNS-резолвер медленнее, чем DoH",
                    detail_ru=f"Системный резолвер в среднем {adv.system_avg_ms} мс против {adv.doh_avg_ms} мс через DoH.",
                    advice_ru="Переключение системного резолвера на более быстрый публичный (или использование DoH) может снизить задержку загрузки страниц.",
                )
            )
    for divergence in adv.divergences:
        if "suspicious=True" not in divergence:
            continue
        name = divergence.split(":", 1)[0].strip()
        findings.append(
            Finding(
                id=f"dns.poisoned_answer.{name}",
                severity="crit",
                title=f"System resolver returned a bogus answer for {name}",
                detail=divergence,
                advice="Compare against a known-good resolver (1.1.1.1/8.8.8.8) or DoH; this can indicate ISP-level DNS injection.",
                title_ru=f"Системный резолвер вернул некорректный ответ для {name}",
                detail_ru=divergence,
                advice_ru="Сравните с заведомо надёжным резолвером (1.1.1.1/8.8.8.8) или DoH; это может указывать на подмену DNS на стороне провайдера.",
            )
        )
    return findings


_EDGE_FAR_MS = 50.0


def path_diversity_findings(pd: PathDiversity) -> list[Finding]:
    findings: list[Finding] = []
    if pd.international_loop:
        countries = ", ".join(pd.detour_countries)
        findings.append(
            Finding(
                id="anycast.international_loop",
                severity="warn",
                title="Anycast routed traffic through another country",
                detail=pd.note or f"Traffic detoured through {countries}.",
                metric="detour_countries",
                value=countries,
                advice="Ask your ISP about local peering/CDN caching for this provider, or use a resolver closer to the intended PoP.",
                title_ru="Anycast завернул трафик через другую страну",
                detail_ru=pd.note_ru or f"Трафик прошёл через {countries}.",
                advice_ru="Спросите провайдера про локальный пиринг/кэширование CDN для этого сервиса, либо используйте резолвер ближе к нужному PoP.",
            )
        )
    for hop in pd.hops:
        if hop.client_rtt_ms is None or hop.edge_rtt_ms is None:
            continue
        delta = hop.client_rtt_ms - hop.edge_rtt_ms
        if delta > _EDGE_FAR_MS:
            findings.append(
                Finding(
                    id=f"anycast.edge_far.{hop.target}",
                    severity="info",
                    title=f"Anycast edge for {hop.target} is far from the client",
                    detail=f"Client RTT {hop.client_rtt_ms} ms vs edge-observed RTT {hop.edge_rtt_ms} ms.",
                    metric="client_rtt_ms",
                    value=hop.client_rtt_ms,
                    threshold=_EDGE_FAR_MS,
                    advice="The last mile to the nearest PoP may be the bottleneck rather than the wider path.",
                    title_ru=f"Anycast-точка для {hop.target} далеко от клиента",
                    detail_ru=f"RTT клиента {hop.client_rtt_ms} мс против RTT со стороны edge {hop.edge_rtt_ms} мс.",
                    advice_ru="Узким местом может быть последняя миля до ближайшего PoP, а не весь остальной путь.",
                )
            )
    return findings


_SCORE_PENALTY = {"ok": 0, "info": 3, "warn": 10, "crit": 25}


def overall_verdict(findings: list[Finding]) -> tuple[str, int, str]:
    score = 100
    status = "ok"
    for f in findings:
        score -= _SCORE_PENALTY[f.severity]
        if _SEVERITY_ORDER[f.severity] > _SEVERITY_ORDER[status]:
            status = f.severity
    score = max(0, score)
    if status in ("ok", "info"):
        return "ok", score, "No problems found on this connection."
    headline = [f.title for f in findings if f.severity == status]
    return status, score, "; ".join(headline[:3])
