from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from netcheck.interpret import overall_verdict
from netcheck.models import Finding, ModuleResult, to_jsonable

SCHEMA_VERSION = 1
SECTION_ORDER = (
    "connection",
    "ip_geo",
    "vpn_assessment",
    "bgp",
    "reputation",
    "latency",
    "path",
    "speed",
)

_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_name(value: str | None, fallback: str = "unknown") -> str:
    cleaned = _UNSAFE_NAME_RE.sub("_", (value or "").strip()).strip("._")
    return cleaned[:32] or fallback


def compact_timestamp(iso: str) -> str:
    # Windows forbids ':' in filenames, so the stamp is the compact ISO form.
    return re.sub(r"[-:]", "", (iso or "").strip()) or "unknown"


def report_filename(asn: str | None, started_at: str, extension: str) -> str:
    return f"report_{sanitize_name(asn)}_{compact_timestamp(started_at)}.{extension.lstrip('.')}"


def flatten_errors(modules: dict[str, ModuleResult]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for section, result in modules.items():
        for error in result.errors:
            entry = to_jsonable(error)
            entry["module"] = result.name or section
            flat.append(entry)
    return flat


def build_report(
    meta: dict[str, Any],
    modules: dict[str, ModuleResult],
    findings: list[Finding],
    raw: dict[str, Any],
) -> dict[str, Any]:
    status, score, summary = overall_verdict(findings)
    report: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "meta": to_jsonable(meta)}
    for section in SECTION_ORDER:
        result = modules.get(section) or ModuleResult(name=section, status="skipped")
        report[section] = to_jsonable(result)
    report["interpretation"] = {
        "overall_status": status,
        "overall_score": score,
        "summary_text": summary,
        "findings": to_jsonable(findings),
    }
    report["errors"] = flatten_errors(modules)
    report["raw"] = to_jsonable(raw)
    return report


def dump_json(report: dict[str, Any]) -> str:
    return json.dumps(to_jsonable(report), allow_nan=False, ensure_ascii=False, indent=2)


def atomic_write(path: Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def egress_asn(report: dict[str, Any]) -> str | None:
    data = (report.get("ip_geo") or {}).get("data") or {}
    return ((data.get("egress_v4") or {}) if isinstance(data, dict) else {}).get("asn")


def write_report(
    report: dict[str, Any], markdown: str, markdown_ru: str, logs_dir: Path
) -> tuple[Path, Path, Path]:
    meta = report.get("meta") or {}
    started = meta.get("started_at", "")
    asn = meta.get("target") or egress_asn(report)
    base = Path(logs_dir)
    json_path = atomic_write(base / report_filename(asn, started, "json"), dump_json(report))
    md_path = atomic_write(base / report_filename(asn, started, "md"), markdown)
    ru_md_path = atomic_write(base / report_filename(asn, started, "ru.md"), markdown_ru)
    return json_path, md_path, ru_md_path


from netcheck.interpret import bufferbloat_consequence

SPARK_CHARS = "▁▂▃▅▇"
_BADGES = {"ok": "🟢", "info": "🟢", "warn": "🟡", "crit": "🔴"}
_SEVERITY_RANK = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
_SEVERITY_WORDS_RU = {"ok": "норма", "info": "инфо", "warn": "предупреждение", "crit": "критично"}
_LOSS_JUMP_PCT = 20.0


def _t(lang: str, en: str, ru: str) -> str:
    return en if lang == "en" else ru


_WARNING_RU = {
    "no ASN was resolved for this target": "для этой цели не удалось определить ASN",
    "no egress IP to check": "нет внешнего IP для проверки",
    "ABUSEIPDB_API_KEY not set — abuse score skipped": "ABUSEIPDB_API_KEY не задан — оценка abuse пропущена",
    "speedtest skipped: --quick": "speedtest пропущен: --quick",
    "speedtest skipped in target mode": "speedtest пропущен в режиме цели",
    "no throughput measured": "пропускная способность не измерена",
}


def _warning(lang: str, text: str) -> str:
    return text if lang == "en" else _WARNING_RU.get(text, text)


def sparkline(values: list[float | None]) -> str:
    numbers = [v for v in values if v is not None]
    if not numbers:
        return ""
    low, high = min(numbers), max(numbers)
    span = high - low
    out: list[str] = []
    for value in values:
        if value is None:
            out.append(" ")
        elif span <= 0:
            out.append(SPARK_CHARS[0])
        else:
            index = int((value - low) / span * (len(SPARK_CHARS) - 1))
            out.append(SPARK_CHARS[index])
    return "".join(out)


def badge(severity: str, emoji: bool, lang: str = "en") -> str:
    if emoji:
        return _BADGES.get(severity, "⚪")
    word = severity if lang == "en" else _SEVERITY_WORDS_RU.get(severity, severity)
    return f"[{word}]"


def first_loss_jump(hops: list[dict]) -> int | None:
    for index, hop in enumerate(hops[:-1]):
        following = hops[index + 1]
        if hop.get("loss_pct", 0.0) >= _LOSS_JUMP_PCT and following.get("loss_pct", 0.0) >= _LOSS_JUMP_PCT:
            return hop.get("ttl")
    return None


def _module(report: dict, section: str) -> dict:
    return report.get(section) or {}


def _data(report: dict, section: str) -> Any:
    return _module(report, section).get("data")


def _num(value: Any) -> str:
    return "—" if value is None else f"{value:g}" if isinstance(value, (int, float)) else str(value)


def _table(headers: list[str], rows: list[list[str]], lang: str = "en") -> list[str]:
    if not rows:
        return [_t(lang, "_No rows._", "_Нет строк._")]
    return (
        ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
        + ["| " + " | ".join(row) + " |" for row in rows]
    )


def _findings(report: dict) -> list[dict]:
    return sorted(
        (report.get("interpretation") or {}).get("findings") or [],
        key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 9),
    )


def _f(finding: dict, field: str, lang: str) -> str:
    if lang == "ru":
        return finding.get(f"{field}_ru") or finding.get(field) or ""
    return finding.get(field) or ""


def _ru_summary(report: dict, status: str) -> str:
    if status in ("ok", "info"):
        return "Проблем на этом соединении не найдено."
    found = [f for f in _findings(report) if f.get("severity") == status]
    return "; ".join(_f(f, "title", "ru") for f in found[:3])


def _header(report: dict, emoji: bool, lang: str = "en") -> list[str]:
    meta = report.get("meta") or {}
    interp = report.get("interpretation") or {}
    target = f" · {_t(lang, 'target', 'цель')} `{meta.get('target')}`" if meta.get("target") else ""
    status = interp.get("overall_status", "ok")
    summary = interp.get("summary_text", "") if lang == "en" else _ru_summary(report, status)
    status_word = status if lang == "en" else _SEVERITY_WORDS_RU.get(status, status)
    return [
        "# netcheck report",
        "",
        f"- {_t(lang, 'Mode', 'Режим')}: `{meta.get('mode', 'auto')}`{target}",
        f"- {_t(lang, 'Started', 'Начало')}: {meta.get('started_at', '?')} · "
        f"{_t(lang, 'finished', 'завершение')}: {meta.get('finished_at', '?')}",
        f"- {_t(lang, 'Host OS', 'ОС хоста')}: {meta.get('host_os', '?')} · "
        f"{_t(lang, 'run id', 'id запуска')} `{meta.get('run_id', '?')}`",
        f"- {_t(lang, 'Verdict', 'Вердикт')}: {badge(status, emoji, lang)} **{status_word}** "
        f"({interp.get('overall_score', 0)}/100) — {summary}",
        "",
    ]


def _tldr(report: dict, emoji: bool, lang: str = "en") -> list[str]:
    found = _findings(report)
    heading = _t(lang, "## TL;DR", "## Коротко")
    if not found:
        return [heading, "", _t(lang, "No problems found on this connection.", "Проблем на этом соединении не найдено."), ""]
    return [heading, ""] + [
        f"- {badge(f.get('severity', 'info'), emoji, lang)} **{_f(f, 'title', lang)}** — {_f(f, 'detail', lang)}"
        for f in found[:5]
    ] + [""]


_SECTION_TITLES = {
    "connection": "## Connection & identity",
    "ip_geo": "## Connection & identity",
    "vpn_assessment": "## VPN / proxy assessment",
    "bgp": "## ASN & BGP intelligence",
    "reputation": "## Reputation",
    "latency": "## Latency",
    "path": "## Path",
    "speed": "## Speed",
}

_SECTION_TITLES_RU = {
    "connection": "## Подключение и идентификация",
    "ip_geo": "## Подключение и идентификация",
    "vpn_assessment": "## Оценка VPN/прокси",
    "bgp": "## ASN и BGP-разведка",
    "reputation": "## Репутация",
    "latency": "## Задержки",
    "path": "## Маршрут",
    "speed": "## Скорость",
}


def _section_title(section: str, lang: str = "en") -> str:
    return _SECTION_TITLES_RU[section] if lang == "ru" else _SECTION_TITLES[section]


_MODULE_STATUS_RU = {"ok": "ок", "partial": "частично", "failed": "ошибка", "skipped": "пропущено"}


def _module_status_word(status: str, lang: str) -> str:
    return status if lang == "en" else _MODULE_STATUS_RU.get(status, status)


def unavailable(report: dict[str, Any], section: str, lang: str = "en") -> str | None:
    module = _module(report, section)
    if module.get("status") in ("ok", "partial") and module.get("data") is not None:
        return None
    detail = "; ".join(f"{e.get('source')}: {e.get('message')}" for e in module.get("errors") or [])
    if not detail:
        detail = "; ".join(_warning(lang, w) for w in module.get("warnings") or [])
    if not detail:
        detail = _t(lang, "no data was collected for this section", "для этого раздела не собраны данные")
    status_word = _module_status_word(module.get("status", "skipped"), lang)
    label = _t(lang, "Not available", "Недоступно")
    return f"_{label} — {status_word}: {detail}._"


def _connection(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("connection", lang)
    conn_note = unavailable(report, "connection", lang)
    geo_note = unavailable(report, "ip_geo", lang)
    if conn_note or geo_note:
        notes = [n for n in (conn_note, geo_note) if n]
        return [title, "", *notes, ""]
    local = _data(report, "connection") or {}
    geo_bundle = _data(report, "ip_geo") or {}
    geo = geo_bundle.get("egress_v4") or {}
    v6 = geo_bundle.get("egress_v6") or {}
    cf = geo_bundle.get("cf_trace") or {}
    rows = [
        [_t(lang, "Interface", "Интерфейс"), f"{local.get('iface_name') or '?'} (MTU {local.get('iface_mtu') or '?'})"],
        [
            _t(lang, "Local address", "Локальный адрес"),
            f"{local.get('local_ipv4') or '?'} / {local.get('local_ipv6') or '—'}",
        ],
        [_t(lang, "Default gateway", "Шлюз по умолчанию"), local.get("default_gateway_v4") or "?"],
        [
            _t(lang, "Egress IPv4", "Внешний IPv4"),
            f"{geo.get('ip') or '?'} ({geo.get('asn') or '?'} {geo.get('as_name') or geo.get('org') or ''})",
        ],
        [_t(lang, "Egress IPv6", "Внешний IPv6"), f"{v6.get('ip') or '—'} ({v6.get('asn') or '—'})"],
        [_t(lang, "Reverse DNS", "Обратный DNS"), geo.get("reverse_dns") or "—"],
        [
            _t(lang, "Location", "Местоположение"),
            f"{geo.get('city') or '?'}, {geo.get('country') or geo.get('country_code') or '?'}",
        ],
        [_t(lang, "Address type", "Тип адреса"), geo.get("ip_type") or _t(lang, "unknown", "неизвестно")],
        [_t(lang, "Cloudflare colo", "Дата-центр Cloudflare"), cf.get("colo") or "—"],
    ]
    lines = [title, ""] + _table([_t(lang, "Field", "Поле"), _t(lang, "Value", "Значение")], rows, lang) + [""]
    if geo_bundle.get("dual_stack_note"):
        lines += [f"> {geo_bundle['dual_stack_note']}", ""]
    return lines


_VPN_VERDICT_RU = {"none": "нет", "likely": "вероятно", "confirmed": "подтверждено", "unknown": "неизвестно"}


def _vpn(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("vpn_assessment", lang)
    note = unavailable(report, "vpn_assessment", lang)
    if note:
        return [title, "", note, ""]
    vpn = _data(report, "vpn_assessment") or {}
    verdict = vpn.get("verdict", "unknown")
    verdict_word = verdict if lang == "en" else _VPN_VERDICT_RU.get(verdict, verdict)
    yes, no = _t(lang, "yes", "да"), _t(lang, "no", "нет")
    lines = [
        title,
        "",
        f"{_t(lang, 'Verdict', 'Вердикт')}: **{verdict_word}** · {_t(lang, 'confidence', 'уверенность')} "
        f"{vpn.get('confidence', 0)} · {_t(lang, 'tunnel interface', 'туннельный интерфейс')} "
        f"{vpn.get('tunnel_iface') or '—'}",
        "",
    ]
    lines += _table(
        [
            _t(lang, "Signal", "Сигнал"),
            _t(lang, "Observed", "Замечен"),
            _t(lang, "Weight", "Вес"),
            _t(lang, "Direction", "Направление"),
            _t(lang, "Note", "Примечание"),
        ],
        [
            [
                s.get("name", ""),
                yes if s.get("observed") else no,
                _num(s.get("weight")),
                s.get("direction", ""),
                s.get("note") or "—",
            ]
            for s in vpn.get("signals") or []
        ],
        lang,
    )
    leak = vpn.get("dns_leak") or {}
    if leak:
        lines += ["", _t(lang, "### DNS leak", "### Утечка DNS"), ""]
        lines += _table(
            [
                _t(lang, "Adapter", "Адаптер"),
                _t(lang, "Configured resolvers", "Настроенные резолверы"),
                _t(lang, "Echoed IP", "Отражённый IP"),
                _t(lang, "Echoed ASN", "Отражённый ASN"),
                _t(lang, "Same ASN as egress", "Тот же ASN, что и внешний"),
            ],
            [
                [
                    a.get("adapter", ""),
                    ", ".join(a.get("configured_resolvers") or []) or "—",
                    a.get("echoed_ip") or "—",
                    a.get("echoed_asn") or "—",
                    {True: yes, False: no, None: "?"}[a.get("matches_egress_asn")],
                ]
                for a in leak.get("per_adapter") or []
            ],
            lang,
        )
        ecs_word = yes if leak.get("ecs_leaked") else no
        note_text = (leak.get("note_ru") or leak.get("note") or "") if lang == "ru" else (leak.get("note") or "")
        lines += [
            "",
            f"{_t(lang, 'EDNS Client Subnet leaked', 'Утечка EDNS Client Subnet')}: {ecs_word}",
            "",
            note_text,
        ]
    return lines + [""]


_ROUTE_STABILITY_RU = {"stable": "стабильный", "unstable": "нестабильный", "unknown": "неизвестно"}


def _bgp(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("bgp", lang)
    note = unavailable(report, "bgp", lang)
    if note:
        return [title, "", note, ""]
    bgp = _data(report, "bgp") or {}
    stability = bgp.get("stability", "unknown")
    stability_word = stability if lang == "en" else _ROUTE_STABILITY_RU.get(stability, stability)
    rows = [
        [_t(lang, "ASN", "ASN"), f"{bgp.get('asn') or '?'} — {bgp.get('holder') or '?'}"],
        [
            _t(lang, "Registry", "Реестр"),
            f"{bgp.get('registry') or '?'} ({_t(lang, 'allocated', 'выделен')} {bgp.get('allocated_at') or '?'})",
        ],
        [_t(lang, "Upstreams", "Аплинки"), ", ".join(bgp.get("upstreams") or []) or "—"],
        [_t(lang, "Peers", "Пиры"), ", ".join(bgp.get("peers") or []) or "—"],
        [_t(lang, "Downstreams", "Клиенты"), ", ".join((bgp.get("downstreams") or [])[:10]) or "—"],
        [
            _t(lang, "Announced prefixes", "Анонсируемые префиксы"),
            f"{bgp.get('prefix_count_v4', 0)} IPv4 / {bgp.get('prefix_count_v6', 0)} IPv6",
        ],
        [
            _t(lang, "Route stability", "Стабильность маршрутов"),
            f"{stability_word} ({len(bgp.get('flaps') or [])} {_t(lang, 'updates in window', 'обновлений в окне')})",
        ],
        [
            _t(lang, "CAIDA ASRank", "CAIDA ASRank"),
            f"#{_num(bgp.get('asrank'))} · {_t(lang, 'cone', 'конус')} {_num(bgp.get('cone_asns'))} "
            f"{_t(lang, 'ASNs', 'ASN')} / {_num(bgp.get('cone_prefixes'))} {_t(lang, 'prefixes', 'префиксов')}",
        ],
        [_t(lang, "PeeringDB", "PeeringDB"), f"{bgp.get('pdb_info_type') or '—'} · {bgp.get('pdb_traffic') or '—'}"],
    ]
    lines = [title, ""] + _table([_t(lang, "Field", "Поле"), _t(lang, "Value", "Значение")], rows, lang)
    ixps = bgp.get("ixps") or []
    if ixps:
        lines += ["", _t(lang, "### IXP presence", "### Присутствие на IX"), ""]
        lines += _table(
            [
                _t(lang, "Exchange", "Точка обмена"),
                _t(lang, "City", "Город"),
                _t(lang, "Country", "Страна"),
                _t(lang, "Speed (Mbps)", "Скорость (Мбит/с)"),
            ],
            [[i.get("name", ""), i.get("city") or "—", i.get("country") or "—", _num(i.get("speed_mbps"))] for i in ixps],
            lang,
        )
    return lines + [""]


_CAPTCHA_RISK_RU = {"unknown": "неизвестен", "low": "низкий", "medium": "средний", "high": "высокий"}


def _reputation(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("reputation", lang)
    note = unavailable(report, "reputation", lang)
    if note:
        return [title, "", note, ""]
    rep = _data(report, "reputation") or {}
    idb = rep.get("internetdb") or {}
    none_word = _t(lang, "none", "нет")
    rows = [
        [_t(lang, "FireHOL hits", "Совпадения FireHOL"), ", ".join(rep.get("firehol_hits") or []) or none_word],
        [
            _t(lang, "Open ports (InternetDB)", "Открытые порты (InternetDB)"),
            ", ".join(str(p) for p in idb.get("ports") or []) or none_word,
        ],
        [_t(lang, "Tags", "Теги"), ", ".join(idb.get("tags") or []) or none_word],
        [_t(lang, "Known CVEs", "Известные CVE"), ", ".join(idb.get("vulns") or []) or none_word],
        [
            _t(lang, "AbuseIPDB", "AbuseIPDB"),
            _num(rep.get("abuseipdb_score")) if rep.get("abuseipdb_score") is not None else _t(lang, "not queried", "не запрошено"),
        ],
    ]
    hits = rep.get("dnsbl_hits")
    if hits is None:
        rows.append([_t(lang, "DNSBL", "DNSBL"), _t(lang, "not run (pass --dnsbl)", "не выполнено (используйте --dnsbl)")])
    else:
        listed = ", ".join(h.get("zone", "") for h in hits) or _t(lang, "no listing", "нет в списках")
        if rep.get("dnsbl_query_blocked"):
            listed += _t(
                lang,
                " · one or more zones answered with their query-error range, which is not a listing",
                " · одна или несколько зон ответили в диапазоне ошибок запроса — это не является листингом",
            )
        rows.append([_t(lang, "DNSBL", "DNSBL"), listed])
    risk = rep.get("captcha_risk", "unknown")
    risk_word = risk if lang == "en" else _CAPTCHA_RISK_RU.get(risk, risk)
    rationale = (rep.get("rationale_ru") or rep.get("rationale") or "") if lang == "ru" else (rep.get("rationale") or "")
    return (
        [title, "", f"{_t(lang, 'Captcha/blocklist risk', 'Риск капчи/блок-листов')}: **{risk_word}** — {rationale}", ""]
        + _table([_t(lang, "Field", "Поле"), _t(lang, "Value", "Значение")], rows, lang)
        + [""]
    )


def _latency(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("latency", lang)
    note = unavailable(report, "latency", lang)
    if note:
        return [title, "", note, ""]
    pings = _data(report, "latency") or []
    lines = [title, ""] + _table(
        [
            _t(lang, "Host", "Хост"),
            _t(lang, "Address", "Адрес"),
            _t(lang, "Method", "Метод"),
            _t(lang, "Avg ms", "Сред. мс"),
            _t(lang, "Min", "Мин"),
            _t(lang, "Max", "Макс"),
            _t(lang, "Jitter", "Джиттер"),
            _t(lang, "Loss", "Потери"),
        ],
        [
            [
                p.get("label", ""),
                p.get("host", ""),
                p.get("method", ""),
                _num(p.get("avg_ms")),
                _num(p.get("min_ms")),
                _num(p.get("max_ms")),
                _num(p.get("jitter_ms")),
                f"{p.get('loss_pct', 0)}%",
            ]
            for p in pings
        ],
        lang,
    )
    if pings:
        lines += ["", "```"]
        lines += [f"{p.get('label', ''):<18}{sparkline(p.get('samples') or [])}" for p in pings]
        lines += ["```"]
    if any(p.get("method") == "tcp" for p in pings):
        lines += [
            "",
            f"> {_t(lang, 'Loss on a `tcp` row counts failed TCP connections, not dropped ICMP packets.', 'Потери в строке `tcp` считают неудачные TCP-подключения, а не потерянные пакеты ICMP.')}",
        ]
    return lines + [""]


def _bar(value: Any) -> str:
    return "#" * int(min(float(value or 0.0), 200.0) / 10)


def _path(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("path", lang)
    note = unavailable(report, "path", lang)
    if note:
        return [title, "", note, ""]
    traces = _data(report, "path") or []
    lines = [title, ""]
    for trace in traces:
        hops = trace.get("hops") or []
        jump = first_loss_jump(hops)
        completed_word = (
            _t(lang, "complete", "завершено") if trace.get("completed") else _t(lang, "incomplete", "не завершено")
        )
        lines += [
            f"### {trace.get('target') or '?'} — {_t(lang, 'backend', 'бэкенд')} `{trace.get('backend', 'none')}`, "
            f"{completed_word}",
            "",
            "```",
        ]
        for hop in hops:
            marker = " <<" if jump is not None and hop.get("ttl") == jump else ""
            lines.append(
                f"{hop.get('ttl', 0):>3}  {(hop.get('ip') or '*'):<39} "
                f"{_num(hop.get('avg_ms')):>8} ms  {hop.get('loss_pct', 0):>5}%  {_bar(hop.get('avg_ms'))}{marker}"
            )
        lines += ["```", ""]
    return lines


def _speed(report: dict, lang: str = "en") -> list[str]:
    title = _section_title("speed", lang)
    note = unavailable(report, "speed", lang)
    if note:
        return [title, "", note, ""]
    speed = _data(report, "speed") or {}
    grade = speed.get("bufferbloat_grade") or "?"
    method = speed.get("method", "none")
    method_word = _t(lang, "none", "нет") if method == "none" else method
    yes, no = _t(lang, "yes", "да"), _t(lang, "no", "нет")

    def yn(value: Any) -> str:
        return {True: yes, False: no, None: "—"}[value]

    rows = [
        [_t(lang, "Method", "Метод"), method_word],
        [_t(lang, "Server", "Сервер"), speed.get("server") or "—"],
        [_t(lang, "Download", "Скачивание"), f"{_num(speed.get('download_mbps'))} {_t(lang, 'Mbps', 'Мбит/с')}"],
        [_t(lang, "Upload", "Отдача"), f"{_num(speed.get('upload_mbps'))} {_t(lang, 'Mbps', 'Мбит/с')}"],
        [_t(lang, "Idle RTT", "RTT в простое"), f"{_num(speed.get('idle_rtt_ms'))} {_t(lang, 'ms', 'мс')}"],
        [
            _t(lang, "Loaded RTT (down / up)", "RTT под нагрузкой (приём / передача)"),
            f"{_num(speed.get('loaded_rtt_down_ms'))} / {_num(speed.get('loaded_rtt_up_ms'))} {_t(lang, 'ms', 'мс')}",
        ],
        [
            _t(lang, "Bufferbloat", "Bufferbloat"),
            f"{_t(lang, 'grade', 'оценка')} {grade} — {_t(lang, 'down', 'приём')} "
            f"+{_num(speed.get('bufferbloat_down_ms'))} {_t(lang, 'ms', 'мс')}, "
            f"{_t(lang, 'up', 'передача')} +{_num(speed.get('bufferbloat_up_ms'))} {_t(lang, 'ms', 'мс')}",
        ],
        [_t(lang, "Netflix OCA on-net", "Netflix OCA в сети"), yn(speed.get("netflix_oca_onnet"))],
    ]
    lines = (
        [title, ""]
        + _table([_t(lang, "Field", "Поле"), _t(lang, "Value", "Значение")], rows, lang)
        + ["", bufferbloat_consequence(grade, lang)]
    )
    attempts = speed.get("tier_attempts") or []
    if attempts:
        lines += ["", _t(lang, "### Cascade", "### Каскад"), ""]
        lines += _table(
            [
                _t(lang, "Tier", "Уровень"),
                _t(lang, "Used", "Использован"),
                _t(lang, "Reason", "Причина"),
                _t(lang, "ms", "мс"),
            ],
            [
                [a.get("tier", ""), yn(a.get("ok")), a.get("reason") or "—", _num(a.get("duration_ms"))]
                for a in attempts
            ],
            lang,
        )
    return lines + [""]


def _problems(report: dict, emoji: bool, lang: str = "en") -> list[str]:
    found = _findings(report)
    heading = _t(lang, "## Problems & recommendations", "## Проблемы и рекомендации")
    if not found:
        return [heading, "", _t(lang, "Nothing to act on.", "Не на что реагировать."), ""]
    lines = [heading, ""]
    for f in found:
        lines.append(f"- {badge(f.get('severity', 'info'), emoji, lang)} **{_f(f, 'title', lang)}** — {_f(f, 'detail', lang)}")
        advice = _f(f, "advice", lang)
        if advice:
            lines.append(f"  - {advice}")
    return lines + [""]


def _diagnostics(report: dict, lang: str = "en") -> list[str]:
    rows = []
    warnings: list[str] = []
    for section in SECTION_ORDER:
        module = _module(report, section)
        errors = "; ".join(f"{e.get('source')}: {e.get('kind')}" for e in module.get("errors") or []) or "—"
        status_word = _module_status_word(module.get("status", "skipped"), lang)
        rows.append([section, status_word, _num(module.get("duration_ms")), errors])
        warnings += list(module.get("warnings") or [])
    heading = _t(lang, "## Run diagnostics", "## Диагностика запуска")
    lines = [heading, ""] + _table(
        [_t(lang, "Module", "Модуль"), _t(lang, "Status", "Статус"), _t(lang, "ms", "мс"), _t(lang, "Errors", "Ошибки")],
        rows,
        lang,
    )
    if warnings:
        lines += [""] + [f"- {_warning(lang, w)}" for w in warnings]
    return lines + [""]


def render_markdown(
    report: dict[str, Any], emoji: bool = True, lang: str = "en", sibling: str | None = None
) -> str:
    lines = _header(report, emoji, lang)
    if sibling:
        link_text = "English" if lang == "ru" else "Русский"
        lines = [lines[0], "", f"[{link_text}]({sibling})"] + lines[1:]
    lines += _tldr(report, emoji, lang)
    lines += _connection(report, lang)
    lines += _vpn(report, lang)
    lines += _bgp(report, lang)
    lines += _reputation(report, lang)
    lines += _latency(report, lang)
    lines += _path(report, lang)
    lines += _speed(report, lang)
    lines += _problems(report, emoji, lang)
    lines += _diagnostics(report, lang)
    return "\n".join(lines).rstrip() + "\n"
