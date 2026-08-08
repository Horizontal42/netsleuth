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


def write_report(report: dict[str, Any], markdown: str, logs_dir: Path) -> tuple[Path, Path]:
    started = (report.get("meta") or {}).get("started_at", "")
    asn = egress_asn(report)
    base = Path(logs_dir)
    json_path = atomic_write(base / report_filename(asn, started, "json"), dump_json(report))
    md_path = atomic_write(base / report_filename(asn, started, "md"), markdown)
    return json_path, md_path
