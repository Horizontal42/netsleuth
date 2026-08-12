"""Интеграционные тесты с реальными API.

Эти тесты используют реальные внешние API и должны запускаться только вручную
с флагом --integration из-за rate limiting и сетевых зависимостей.

Запуск:
    pytest tests/integration/ -v --integration

Требования:
    - Стабильное интернет-соединение
    - Отсутствие блокировок внешних API
    - Rate limits могут вызывать пропуски тестов
"""

import pytest
import httpx


pytestmark = pytest.mark.integration


class TestRIPEstatAPI:
    """Интеграционные тесты для RIPEstat API."""

    async def test_real_ripestat_asn_lookup(self):
        """Тест реального запроса к RIPEstat API для ASN lookup."""
        from netsleuth.bgp import get_asn_info
        
        result = await get_asn_info("8.8.8.8")
        
        assert result is not None
        assert "asn" in result or result.get("org_name") is not None
        # Google DNS должен возвращать AS15169
        if result.get("asn"):
            assert "15169" in str(result.get("asn", ""))

    async def test_ripestat_rate_limiting(self):
        """Проверка обработки rate limiting от RIPEstat."""
        from netsleuth.bgp import get_asn_info
        
        # Делаем несколько быстрых запросов
        results = []
        for ip in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
            result = await get_asn_info(ip)
            results.append(result)
        
        # Хотя бы некоторые запросы должны успешно выполниться
        assert any(r is not None for r in results)


class TestIPInfoAPI:
    """Интеграционные тесты для ip-api.com и подобных."""

    async def test_real_ip_geo_lookup(self):
        """Тест реального запроса геолокации IP."""
        from netsleuth.ip_geo import fetch_ipinfo
        
        result = await fetch_ipinfo("8.8.8.8")
        
        assert result is not None
        # Google DNS должен быть в США
        assert result.get("country") in ["US", "United States", "США"]


class TestCloudflareSpeedtest:
    """Интеграционные тесты для Cloudflare speedtest."""

    async def test_real_speedtest_download(self):
        """Тест реального скачивания для speedtest."""
        from netsleuth.speed import run_speedtest_cloudflare
        
        result = await run_speedtest_cloudflare()
        
        assert result is not None
        assert result.download_mbps > 0
        # Разумные пределы: от 0.1 Mbps до 10 Gbps
        assert 0.1 < result.download_mbps < 10000


class TestDNSResolution:
    """Интеграционные тесты для DNS резолвинга."""

    async def test_real_dns_lookup(self):
        """Тест реального DNS запроса."""
        from netsleuth.probes.dns_advanced import resolve_dns
        
        result = await resolve_dns("google.com", "A")
        
        assert result is not None
        assert len(result) > 0
        # Должен вернуть хотя бы один IPv4 адрес
        assert any(r.startswith("142.") or r.startswith("172.") for r in result)


class TestTraceroute:
    """Интеграционные тесты для traceroute."""

    @pytest.mark.skip(reason="Требует root прав и может быть медленным")
    async def test_real_traceroute(self):
        """Тест реальной трассировки до публичного сервера."""
        from netsleuth.probes.traceroute import run_traceroute
        
        result = await run_traceroute("8.8.8.8", max_hops=10)
        
        assert result is not None
        assert len(result.hops) > 0
        # Первый хоп обычно шлюз по умолчанию
        assert result.hops[0].rtt_avg is not None


class TestTLSCertificates:
    """Интеграционные тесты для TLS сертификатов."""

    async def test_real_tls_handshake(self):
        """Тест реального TLS handshake."""
        from netsleuth.probes.tls_rtt import check_tls
        
        result = await check_tls("google.com", 443)
        
        assert result is not None
        assert result.valid is True
        assert result.rtt_ms > 0


@pytest.mark.asyncio
async def test_integration_smoke_test():
    """Дымовой тест для проверки доступности всех внешних API."""
    apis_available = {
        "ripestat": False,
        "ipinfo": False,
        "cloudflare": False,
        "dns": False,
    }
    
    # Проверяем доступность каждого API
    try:
        from netsleuth.bgp import get_asn_info
        result = await get_asn_info("8.8.8.8")
        apis_available["ripestat"] = result is not None
    except Exception:
        pass
    
    try:
        from netsleuth.ip_geo import fetch_ipinfo
        result = await fetch_ipinfo("8.8.8.8")
        apis_available["ipinfo"] = result is not None
    except Exception:
        pass
    
    try:
        from netsleuth.probes.dns_advanced import resolve_dns
        result = await resolve_dns("google.com", "A")
        apis_available["dns"] = len(result) > 0
    except Exception:
        pass
    
    # Хотя бы 2 из 4 API должны быть доступны
    assert sum(apis_available.values()) >= 2, f"Слишком много недоступных API: {apis_available}"
