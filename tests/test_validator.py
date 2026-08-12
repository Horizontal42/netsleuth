"""Тесты для модуля валидации входных данных."""

import pytest
import typer

from netsleuth.validator import (
    validate_bind_address,
    validate_port,
    validate_target,
)


class TestValidateTarget:
    """Тесты валидации target."""

    def test_valid_public_ipv4(self):
        """Валидный публичный IPv4 должен проходить."""
        assert validate_target("8.8.8.8") == "8.8.8.8"
        assert validate_target("1.1.1.1") == "1.1.1.1"
        assert validate_target("93.184.216.34") == "93.184.216.34"

    def test_valid_hostname(self):
        """Валидный hostname должен проходить."""
        assert validate_target("google.com") == "google.com"
        assert validate_target("example.org") == "example.org"
        assert validate_target("my-server.example.com") == "my-server.example.com"

    def test_localhost_rejected(self):
        """Localhost должен быть отклонён."""
        with pytest.raises(typer.BadParameter) as exc_info:
            validate_target("127.0.0.1")
        assert "private/reserved" in str(exc_info.value).lower()

    def test_private_class_a_rejected(self):
        """Private Class A должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_target("10.0.0.1")
        with pytest.raises(typer.BadParameter):
            validate_target("10.255.255.255")

    def test_private_class_c_rejected(self):
        """Private Class C должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_target("192.168.0.1")
        with pytest.raises(typer.BadParameter):
            validate_target("192.168.255.255")

    def test_private_class_b_rejected(self):
        """Private Class B должен быть отклонён."""
        for i in range(16, 32):
            with pytest.raises(typer.BadParameter):
                validate_target(f"172.{i}.0.1")

    def test_multicast_rejected(self):
        """Multicast должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_target("224.0.0.1")
        with pytest.raises(typer.BadParameter):
            validate_target("239.255.255.255")

    def test_reserved_rejected(self):
        """Reserved addresses должны быть отклонены."""
        with pytest.raises(typer.BadParameter):
            validate_target("240.0.0.1")
        with pytest.raises(typer.BadParameter):
            validate_target("0.0.0.0")

    def test_ipv6_localhost_rejected(self):
        """IPv6 localhost должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_target("::1")

    def test_ipv6_link_local_rejected(self):
        """IPv6 link-local должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_target("fe80::1")

    def test_ipv6_unique_local_rejected(self):
        """IPv6 unique local должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_target("fc00::1")
        with pytest.raises(typer.BadParameter):
            validate_target("fd00::1")


class TestValidateBindAddress:
    """Тесты валидации bind address."""

    def test_valid_ipv4(self):
        """Валидный IPv4 должен проходить."""
        assert validate_bind_address("0.0.0.0") == "0.0.0.0"
        assert validate_bind_address("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        """Валидный IPv6 должен проходить."""
        assert validate_bind_address("::") == "::"
        assert validate_bind_address("::1") == "::1"

    def test_invalid_string_rejected(self):
        """Невалидная строка должна быть отклонена."""
        with pytest.raises(typer.BadParameter) as exc_info:
            validate_bind_address("not-an-ip")
        assert "not a valid IP address" in str(exc_info.value)

    def test_invalid_port_number(self):
        """Невалидный порт должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_bind_address("99999.99999.99999.99999")


class TestValidatePort:
    """Тесты валидации порта."""

    def test_valid_ports(self):
        """Валидные порты должны проходить."""
        assert validate_port(1) == 1
        assert validate_port(80) == 80
        assert validate_port(443) == 443
        assert validate_port(8080) == 8080
        assert validate_port(65535) == 65535

    def test_port_zero_rejected(self):
        """Порт 0 должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_port(0)

    def test_negative_port_rejected(self):
        """Отрицательный порт должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_port(-1)

    def test_port_too_high_rejected(self):
        """Порт > 65535 должен быть отклонён."""
        with pytest.raises(typer.BadParameter):
            validate_port(65536)
        with pytest.raises(typer.BadParameter):
            validate_port(99999)
