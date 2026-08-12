#!/usr/bin/env bash
set -euo pipefail

# Netsleuth Development Setup Script
# This script sets up the development environment for netsleuth contributors

echo "🔧 Setting up netsleuth development environment..."

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ uv not found. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

echo "✅ uv found: $(uv --version)"

# Install Python dependencies
echo "📦 Installing dependencies..."
uv sync --extra tcptrace --extra ndt7

# Install pre-commit hooks
echo "🪝 Installing pre-commit hooks..."
uv run pre-commit install

# Run initial checks
echo "🧪 Running initial tests..."
uv run pytest -q

echo "✅ Development environment ready!"
echo ""
echo "Next steps:"
echo "  1. Review CONTRIBUTING.md for contribution guidelines"
echo "  2. Run 'uv run pytest' to verify everything works"
echo "  3. Start coding! 🚀"
