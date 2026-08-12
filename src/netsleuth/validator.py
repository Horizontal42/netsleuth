"""Валидация входных данных для безопасности."""

from __future__ import annotations

import ipaddress
from typing import Final

import typer

# Запрещённые префиксы (private, reserved, multicast)
FORBIDDEN_PREFIXES: Final = [
    "127.",      # localhost
    "0.",        # current network
    "10.",       # private class A
    "192.168.",  # private class C
    "172.16.",   # private class B (начало диапазона)
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "224.",      # multicast
    "240.",      # reserved
    "::1",       # IPv6 localhost
    "fe80:",     # IPv6 link-local
    "fc00:",     # IPv6 unique local
    "fd00:",     # IPv6 unique local
]


def validate_target(value: str) -> str:
    """Валидировать целевой адрес (target).
    
    Проверяет, что адрес не является private/reserved IP.
    
    Args:
        value: IP-адрес или hostname для проверки
        
    Returns:
        Оригинальное значение если валидно
        
    Raises:
        typer.BadParameter: Если адрес запрещён
    """
    # Пропускаем hostnames (содержат буквы)
    if any(c.isalpha() for c in value):
        return value
    
    # Проверка на запрещённые префиксы
    value_lower = value.lower()
    for prefix in FORBIDDEN_PREFIXES:
        if value_lower.startswith(prefix.lower()):
            raise typer.BadParameter(
                f"Target '{value}' cannot be a private/reserved IP address. "
                "Please use a public IP or hostname."
            )
    
    # Попытка распарсить как IP для дополнительной проверки
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_reserved or ip.is_multicast:
            raise typer.BadParameter(
                f"Target '{value}' is a private/reserved/multicast address. "
                "Please use a public IP address."
            )
    except ValueError:
        # Не IP-адрес (возможно hostname), это ок
        pass
    
    return value


def validate_bind_address(value: str) -> str:
    """Валидировать адрес для привязки (--my-server).
    
    Args:
        value: IP-адрес для проверки
        
    Returns:
        Оригинальное значение если валидно
        
    Raises:
        typer.BadParameter: Если адрес невалиден
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise typer.BadParameter(
            f"'{value}' is not a valid IP address for --my-server"
        )
    
    return value


def validate_port(value: int) -> int:
    """Валидировать номер порта.
    
    Args:
        value: Номер порта
        
    Returns:
        Номер порта если валиден
        
    Raises:
        typer.BadParameter: Если порт вне диапазона
    """
    if not (1 <= value <= 65535):
        raise typer.BadParameter(
            f"Port {value} must be between 1 and 65535"
        )
    return value
