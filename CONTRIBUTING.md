# Руководство для контрибьюторов Netsleuth

Спасибо за интерес к проекту! Это руководство поможет вам начать вносить свой вклад.

## 🚀 Быстрый старт

### 1. Настройка окружения

```bash
# Клонируйте репозиторий
git clone https://github.com/egorovandrey/netsleuth.git
cd netsleuth

# Установите uv (если ещё не установлен)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Создайте виртуальное окружение и установите зависимости
uv sync --extra tcptrace --extra ndt7

# Установите pre-commit хуки
uv run pre-commit install
```

### 2. Запуск тестов

```bash
# Все тесты
uv run pytest

# Тесты с покрытием
uv run pytest --cov=src/netsleuth --cov-report=html

# Конкретный тест
uv run pytest tests/test_exporter.py -v
```

### 3. Линтинг и форматирование

```bash
# Проверка стиля
uv run flake8 src/netsleuth

# Форматирование кода
uv run black src/netsleuth tests

# Проверка типов
uv run mypy src/netsleuth --ignore-missing-imports
```

## 📝 Как добавить новый источник геоданных

1. Создайте новый файл в `src/netsleuth/geo/` (например, `new_provider.py`)
2. Реализуйте интерфейс:

```python
from typing import Optional
from dataclasses import dataclass

@dataclass
class GeoResult:
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[int] = None
    org: Optional[str] = None

async def fetch_geo(ip: str) -> Optional[GeoResult]:
    """Получить геоданные для IP."""
    # Ваша реализация
    pass
```

3. Добавьте импорт в `src/netsleuth/geo/__init__.py`
4. Напишите тесты в `tests/test_new_provider.py`
5. Обновите документацию

## 🧪 Как написать тест для новой пробы

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_my_probe():
    # Arrange
    with patch('netsleuth.my_probe.httpx.get') as mock_get:
        mock_get.return_value = {"status": "ok"}
        
        # Act
        result = await run_probe("8.8.8.8")
        
        # Assert
        assert result.status == "ok"
        mock_get.assert_called_once()
```

**Важно:**
- Все HTTP-запросы должны быть замокированы
- Используйте фикстуры из `tests/conftest.py`
- Добавляйте тесты на граничные случаи

## ✅ Чеклист перед Pull Request

- [ ] Код отформатирован (`black src/netsleuth tests`)
- [ ] Нет нарушений flake8 (`flake8 src/netsleuth`)
- [ ] Все тесты проходят (`pytest`)
- [ ] Покрытие не уменьшилось (минимум 60%)
- [ ] Добавлены docstrings для публичных функций
- [ ] Обновлена документация (если нужно)
- [ ] Pre-commit хуки пройдены

## 🏗️ Архитектура проекта

```
src/netsleuth/
├── cli.py           # Точка входа, CLI аргументы
├── config.py        # Конфигурация и настройки
├── models.py        # Датаклассы для данных
├── probes/          # Модули проб (speed, latency, etc.)
├── geo/             # Геоданные и ASN lookup
├── reputation.py    # Проверка по чёрным спискам
├── interpret.py     # Интерпретация результатов
└── exporter.py      # Экспорт в Markdown/JSON
```

Основная статья: [`ARCHITECTURE.ru.md`](ARCHITECTURE.ru.md)

## 🐛 Сообщение об ошибках

При создании issue укажите:
1. Версию Python (`python --version`)
2. Версию netsleuth (`netsleuth --version`)
3. ОС и версию
4. Команду запуска
5. Полный вывод ошибки
6. Скриншот (если применимо)

## 💡 Идеи для улучшений

Ищем помощь в следующих областях:
- [ ] Поддержка новых протоколов (QUIC, HTTP/3)
- [ ] Графический интерфейс (TUI/GUI)
- [ ] Интеграция с Prometheus/Grafana
- [ ] Поддержка IPv6-only хостов
- [ ] Локализация на другие языки

## 📞 Контакты

- GitHub Issues: [egorovandrey/netsleuth/issues](https://github.com/egorovandrey/netsleuth/issues)
- Telegram: @your_channel (если есть)

---

**Спасибо за ваш вклад!** 🎉
