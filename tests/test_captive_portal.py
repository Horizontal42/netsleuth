from __future__ import annotations

import httpx

from netsleuth.interpret import captive_portal_findings
from netsleuth.models import CaptivePortal
from netsleuth.probes.captive_portal import (
    check_captive_portal,
    classify_portal_response,
)

URL = "http://cp.cloudflare.com/generate_204"


def test_classify_204_with_empty_body_is_clean():
    assert classify_portal_response(URL, 204, "", None) == ("clean", "204 with an empty body, as expected")


def test_classify_204_with_a_body_is_suspect():
    verdict, _ = classify_portal_response(URL, 204, "unexpected", None)
    assert verdict == "suspect"


def test_classify_200_with_a_body_is_portal():
    verdict, _ = classify_portal_response(URL, 200, "<html>login</html>", None)
    assert verdict == "portal"


def test_classify_302_to_the_same_host_is_still_a_redirect_status_portal():
    verdict, evidence = classify_portal_response(URL, 302, "", "http://cp.cloudflare.com/login")
    assert verdict == "portal"
    assert "302" in evidence


def test_classify_302_to_a_different_host_is_portal():
    verdict, evidence = classify_portal_response(URL, 302, "", "http://portal.example.net/login")
    assert verdict == "portal"


def test_classify_511_is_portal():
    assert classify_portal_response(URL, 511, "", None)[0] == "portal"


def test_classify_500_is_suspect():
    assert classify_portal_response(URL, 500, "", None)[0] == "suspect"


def test_classify_no_response_is_error():
    assert classify_portal_response(URL, None, "", None) == ("error", "no response")


async def test_check_captive_portal_detects_a_redirect(httpx_mock):
    httpx_mock.add_response(url=URL, status_code=302, headers={"location": "http://portal.example.net/login"})
    async with httpx.AsyncClient() as client:
        result = await check_captive_portal(client, [URL], timeout=5.0)
    assert result.detected is True
    assert result.verdict == "portal"
    assert result.portal_url == URL


async def test_check_captive_portal_clean_connection(httpx_mock):
    httpx_mock.add_response(url=URL, status_code=204)
    async with httpx.AsyncClient() as client:
        result = await check_captive_portal(client, [URL], timeout=5.0)
    assert result.detected is False
    assert result.verdict == "clean"


async def test_check_captive_portal_all_ambiguous_is_suspect(httpx_mock):
    httpx_mock.add_response(url=URL, status_code=500)
    async with httpx.AsyncClient() as client:
        result = await check_captive_portal(client, [URL], timeout=5.0)
    assert result.detected is False
    assert result.verdict == "suspect"


def test_captive_portal_findings_fires_crit_when_detected():
    cp = CaptivePortal(detected=True, verdict="portal", portal_url=URL, note="redirected", note_ru="редирект")
    findings = captive_portal_findings(cp)
    assert [f.id for f in findings] == ["net.captive_portal"]
    assert findings[0].severity == "crit"


def test_captive_portal_findings_fires_warn_when_suspect():
    cp = CaptivePortal(detected=False, verdict="suspect", note="ambiguous", note_ru="неоднозначно")
    findings = captive_portal_findings(cp)
    assert [f.id for f in findings] == ["net.captive_portal_suspect"]
    assert findings[0].severity == "warn"


def test_captive_portal_findings_silent_when_clean():
    assert captive_portal_findings(CaptivePortal(detected=False, verdict="clean")) == []
