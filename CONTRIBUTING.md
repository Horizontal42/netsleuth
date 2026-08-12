# Руководство для контрибьюторов netsleuth

Спасибо за интерес к проекту netsleuth! Это руководство поможет вам начать вносить свой вклад.

## 🚀 Быстрый старт

### 1. Установка зависимостей

```bash
# Клонируйте репозиторий
git clone https://github.com/netsleuth/netsleuth.git
cd netsleuth

# Установите uv (менеджер пакетов)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Синхронизируйте зависимости
uv sync --extra tcptrace --extra ndt7

# Установите pre-commit хуки
uv run pre-commit install
```

### 2. Запуск тестов

```bash
# Все тесты
uv run pytest

# Тесты с покрытием
uv run pytest --cov=src/netsleuth --cov-report=term-missing

# Конкретный тест
uv run pytest tests/test_cli.py -v
```

### 3. Линтинг и форматирование

```bash
# Проверка стиля
uv run flake8 src/netsleuth

# Авто-форматирование (ruff)
uv run ruff format src/netsleuth

# Проверка типов
uv run mypy src/netsleuth
```

---

## 📁 Структура проекта

```
netsleuth/
├── src/netsleuth/       # Исходный код
│   ├── cli.py           # CLI интерфейс (typer)
│   ├── config.py        # Конфигурация и настройки
│   ├── models.py        # Датаклассы и модели данных
│   ├── bgp.py           # BGP и ASN информация
│   ├── geoip.py         # Геолокация IP
│   ├── latency.py       # Измерение задержек
│   ├── path.py          # Traceroute и анализ пути
│   ├── speed.py         # Speedtest и bufferbloat
│   ├── reputation.py    # Проверка IP репутации
│   ├── exporter.py      # Генерация отчётов
│   └── interpret.py     # Интерпретация результатов
├── tests/               # Тесты
├── .github/workflows/   # CI/CD пайплайны
└── docs/                # Документация
```

---

## 🔧 Как добавить новый источник геоданных

### Пример: Добавление GeoIP провайдера

1. **Создайте функцию в `geoip.py`:**

```python
async def fetch_geolocation_new_provider(ip: str) -> dict[str, Any]:
    """Получает геоданные от нового провайдера.
    
    Args:
        ip: IP адрес для поиска
        
    Returns:
        Dict с ключами: country, city, org, asn
        
    Raises:
        httpx.HTTPError: Если API недоступен
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.newprovider.com/geo/{ip}",
            timeout=5.0
        )
        response.raise_for_status()
        return parse_geolocation_response(response.json())
```

2. **Добавьте парсер ответа:**

```python
def parse_geolocation_response(payload: dict) -> dict[str, Any]:
    """Извлекает поля из ответа API."""
    return {
        "country": payload.get("country_name"),
        "city": payload.get("city"),
        "org": payload.get("org"),
        "asn": payload.get("asn"),
    }
```

3. **Интегрируйте в основной пайплайн:**

В `cli.py` найдите `gather_identity()` и добавьте вызов:

```python
geo_new = await fetch_geolocation_new_provider(ip)
```

4. **Напишите тест:**

Создайте `tests/test_geoip_new_provider.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_fetch_geolocation_new_provider(httpx_mock):
    httpx_mock.add_response(
        url="https://api.newprovider.com/geo/8.8.8.8",
        json={"country_name": "US", "city": "Mountain View"}
    )
    
    from netsleuth.geoip import fetch_geolocation_new_provider
    result = await fetch_geolocation_new_provider("8.8.8.8")
    
    assert result["country"] == "US"
    assert result["city"] == "Mountain View"
```

---

## 🧪 Как написать тест для новой пробы

### Шаблон теста

```python
"""Тесты для модуля <module_name>."""

import pytest
from unittest.mock import patch, MagicMock

from netsleuth.<module> import <function_name>


class TestFunctionName:
    """Тесты для <function_name>."""
    
    @pytest.mark.asyncio
    async def test_success_case(self, httpx_mock):
        """Тестирует успешный сценарий."""
        # Arrange
        httpx_mock.add_response(...)
        
        # Act
        result = await <function_name>(...)
        
        # Assert
        assert result.expected_field == "expected_value"
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Тестирует обработку ошибок."""
        with pytest.raises(ExpectedError):
            await <function_name>(invalid_input)
    
    @pytest.mark.asyncio
    async def test_edge_case_empty_input(self):
        """Тестирует граничный случай."""
        result = await <function_name>("")
        assert result is None
```

### Мокирование HTTP запросов

```python
@pytest.mark.asyncio
async def test_with_httpx_mock(httpx_mock):
    """httpx_mock автоматически мокирует httpx запросы."""
    
    # Добавляем ожидаемый запрос
    httpx_mock.add_response(
        url="https://api.example.com/data",
        method="GET",
        status_code=200,
        json={"key": "value"}
    )
    
    # Вызываем функцию
    result = await fetch_data()
    
    # Проверяем что запрос был сделан
    request = httpx_mock.get_request()
    assert request.url == "https://api.example.com/data"
```

---

## ✅ Чеклист перед Pull Request

Перед отправкой PR убедитесь:

- [ ] Все тесты проходят: `uv run pytest`
- [ ] Покрытие не уменьшилось (минимум 60%)
- [ ] Линтер не находит ошибок: `uv run flake8 src/netsleuth`
- [ ] Типизация корректна: `uv run mypy src/netsleuth`
- [ ] Код отформатирован: `uv run ruff format src/netsleuth`
- [ ] Добавлены docstrings для публичных функций
- [ ] Добавлены тесты для нового функционала
- [ ] Обновлена документация (если нужно)
- [ ] Pre-commit хуки проходят: `uv run pre-commit run --all-files`

---

## 📝 Стиль кода

### Именование

- **Функции**: `snake_case` (`fetch_geolocation`)
- **Классы**: `PascalCase` (`SpeedResult`)
- **Константы**: `UPPER_CASE` (`MAX_RETRIES`)
- **Приватные функции**: `_prefix` (`_parse_response`)

### Docstrings

Используйте Google style:

```python
def calculate_latency(samples: list[float]) -> float:
    """Вычисляет среднюю задержку из списка семплов.
    
    Args:
        samples: Список задержек в миллисекундах
        
    Returns:
        Средняя задержка, или 0.0 если список пуст
        
    Raises:
        ValueError: Если есть отрицательные значения
    """
    if not samples:
        return 0.0
    
    if any(s < 0 for s in samples):
        raise ValueError("Latency cannot be negative")
    
    return sum(samples) / len(samples)
```

### Type hints

Все публичные функции должны иметь аннотации типов:

```python
from typing import Any, Optional

def process_ip(ip: str, timeout: float = 5.0) -> Optional[dict[str, Any]]:
    ...
```

---

## 🐛 Отладка

### Логирование

Включите дебаг логирование:

```bash
netsleuth <target> --watch --verbose
```

### Отладка тестов

```bash
# Запустить с выводом print()
uv run pytest -s tests/test_file.py::test_name

# Остановиться на первой ошибке
uv run pytest -x tests/

# Запустить последний упавший тест
uv run pytest --lf
```

---

## 📞 Вопросы и поддержка

- **GitHub Issues**: Для багов и фич https://github.com/netsleuth/netsleuth/issues
- **Discussions**: Для вопросов https://github.com/netsleuth/netsleuth/discussions

---

## 🎯 Идеи для контрибьюшена

### Начинающим

- [ ] Добавить docstrings к функциям без документации
- [ ] Исправить опечатки в README
- [ ] Добавить тесты для существующих функций
- [ ] Улучшить сообщения об ошибках

### Продвинутым

- [ ] Добавить новый источник геоданных
- [ ] Реализовать кэширование API запросов
- [ ] Оптимизировать производительность NetsetIndex
- [ ] Добавить поддержку IPv6 в traceroute
- [ ] Создать GUI для результатов

---

Спасибо за ваш вклад! 🎉
