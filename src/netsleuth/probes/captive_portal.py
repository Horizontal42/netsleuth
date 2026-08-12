from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from netsleuth.models import CaptivePortal, PortalCheck

_REDIRECT_STATUSES = (301, 302, 307, 511)


def classify_portal_response(
    url: str,
    status: int | None,
    body: str,
    location: str | None,
    expected_status: int = 204,
) -> tuple[str, str]:
    if status is None:
        return "error", "no response"
    if status == expected_status and not body:
        return "clean", f"{status} with an empty body, as expected"
    if status in _REDIRECT_STATUSES:
        return "portal", f"redirected ({status}) to {location or '?'}"
    if location:
        requested_host = urlsplit(url).netloc
        redirect_host = urlsplit(location).netloc
        if redirect_host and redirect_host != requested_host:
            return "portal", f"redirected to a different host ({redirect_host})"
    if status == 200 and body:
        return "portal", f"200 with a non-empty body instead of the expected {expected_status}"
    return "suspect", f"unexpected status {status}"


async def check_captive_portal(
    client: httpx.AsyncClient,
    urls: list[str],
    *,
    expected_status: int = 204,
    timeout: float,
) -> CaptivePortal:
    checks: list[PortalCheck] = []
    for url in urls:
        try:
            response = await client.get(url, follow_redirects=False, timeout=timeout)
            verdict, evidence = classify_portal_response(
                url, response.status_code, response.text, response.headers.get("location"), expected_status
            )
        except httpx.HTTPError as exc:
            verdict, evidence = "error", str(exc)
            checks.append(PortalCheck(url=url, status=None, verdict=verdict, evidence=evidence))
            continue
        checks.append(PortalCheck(url=url, status=response.status_code, verdict=verdict, evidence=evidence))

    portal_checks = [c for c in checks if c.verdict == "portal"]
    if portal_checks:
        return CaptivePortal(
            detected=True,
            verdict="portal",
            checks=checks,
            portal_url=portal_checks[0].url,
            note=f"Captive portal detected: {portal_checks[0].evidence}.",
            note_ru=f"Обнаружен captive portal: {portal_checks[0].evidence}.",
        )
    if checks and all(c.verdict in ("suspect", "error") for c in checks):
        return CaptivePortal(
            detected=False,
            verdict="suspect",
            checks=checks,
            note="Every check returned an ambiguous response; a captive portal is possible but not confirmed.",
            note_ru="Все проверки вернули неоднозначный ответ; captive portal возможен, но не подтверждён.",
        )
    return CaptivePortal(detected=False, verdict="clean", checks=checks)
