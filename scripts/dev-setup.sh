#!/bin/bash
# Скрипт быстрой настройки окружения для разработчиков Netsleuth

set -e

echo "🚀 Настройка окружения Netsleuth..."

# Проверка наличия uv
if ! command -v uv &> /dev/null; then
    echo "⚠️  uv не найден. Устанавливаю..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.local/bin/env 2>/dev/null || true
fi

# Создание виртуального окружения
echo "📦 Установка зависимостей..."
uv sync --extra tcptrace --extra ndt7

# Установка pre-commit хуков
echo "🔧 Установка pre-commit хуков..."
uv run pre-commit install

# Запуск тестов для проверки
echo "🧪 Запуск тестов для проверки установки..."
uv run pytest -q

echo ""
echo "✅ Настройка завершена!"
echo ""
echo "Полезные команды:"
echo "  uv run pytest              - запустить все тесты"
echo "  uv run pytest --cov        - тесты с покрытием"
echo "  uv run flake8 src/netsleuth - проверка стиля"
echo "  uv run mypy src/netsleuth   - проверка типов"
echo "  uv run netsleuth --help    - справка по CLI"
echo ""
