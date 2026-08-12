"""Бенчмарки для критических по производительности функций netsleuth."""

import pytest
from ipaddress import IPv4Network, IPv6Network


class TestReputationBenchmarks:
    """Бенчмарки для модуля reputation.py."""

    def test_netset_index_lookup_performance(self, benchmark):
        """Тест производительности поиска в NetsetIndex.
        
        Цель: < 1ms на поиск при 10K префиксов в памяти.
        """
        from netsleuth.reputation import NetsetIndex
        
        # Создаем индекс с 10K префиксов
        prefixes = [
            IPv4Network(f"10.{i//256}.{i%256}.0/24")
            for i in range(10000)
        ]
        
        index = NetsetIndex(prefixes, "test_netset")
        
        # Тестируем производительность поиска
        def lookup():
            return index.hits(IPv4Network("10.50.100.0/24"))
        
        result = benchmark(lookup)
        assert isinstance(result, bool)

    def test_netset_index_large_dataset(self, benchmark):
        """Тест производительности на большом датасете (100K префиксов)."""
        from netsleuth.reputation import NetsetIndex
        
        prefixes = [
            IPv4Network(f"{i//65536}.{(i//256)%256}.{i%256}.0/24")
            for i in range(100000)
        ]
        
        index = NetsetIndex(prefixes, "large_test")
        
        def lookup():
            return index.hits(IPv4Network("50.100.150.0/24"))
        
        result = benchmark(lookup)
        assert isinstance(result, bool)


class TestBGPBenchmarks:
    """Бенчмарки для BGP-модулей."""

    def test_asn_lookup_performance(self, benchmark):
        """Тест производительности ASN lookup."""
        from netsleuth.bgp import get_asn_info
        
        async def lookup():
            return await get_asn_info("8.8.8.8")
        
        # Асинхронный бенчмарк
        result = benchmark.pedantic(
            lambda: lookup(),
            iterations=10,
            rounds=5
        )
        assert result is not None


class TestSpeedMathBenchmarks:
    """Бенчмарки для математических операций speedtest."""

    def test_percentile_calculation(self, benchmark):
        """Тест производительности расчета перцентилей."""
        from netsleuth.stats import percentile
        
        data = list(range(10000))
        
        def calc_p95():
            return percentile(data, 95)
        
        result = benchmark(calc_p95)
        assert result == 9500

    def test_bufferbloat_grading(self, benchmark):
        """Тест производительности grading bufferbloat."""
        from netsleuth.interpret import grade_bufferbloat
        from netsleuth.config import BufferbloatBands
        
        bands = BufferbloatBands()
        
        def grade():
            return grade_bufferbloat(100, 50, bands)
        
        result = benchmark(grade)
        assert result in ["A", "B", "C", "D", "F"]


class TestTraceparseBenchmarks:
    """Бенчмарки для парсинга трассировок."""

    def test_hop_parsing_performance(self, benchmark):
        """Тест производительности парсинга хопов."""
        from netsleuth.traceparse import parse_mtr_output
        
        # Симуляция вывода mtr с 50 хопами
        sample_output = "\n".join([
            f"| {i}| 192.168.{i//256}.{i%256}| 0.5| 0.2| 0.1| 0.0|"
            for i in range(50)
        ])
        
        def parse():
            return parse_mtr_output(sample_output)
        
        result = benchmark(parse)
        assert len(result) == 50
