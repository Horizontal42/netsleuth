#!/usr/bin/env python3
"""Скрипт для поиска функций без docstrings."""

import ast
import sys
from pathlib import Path


class DocstringChecker(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.missing = []

    def visit_FunctionDef(self, node):
        if not ast.get_docstring(node):
            # Пропускаем приватные функции и дюндеры
            if not node.name.startswith('_') or node.name in ('__init__', '__enter__', '__exit__'):
                # Проверяем только публичные функции
                if not node.name.startswith('_'):
                    self.missing.append((node.lineno, node.name))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)


def check_file(filepath: Path) -> list[tuple[int, str]]:
    try:
        source = filepath.read_text(encoding='utf-8')
        tree = ast.parse(source)
        checker = DocstringChecker(str(filepath))
        checker.visit(tree)
        return checker.missing
    except Exception as e:
        print(f"Error parsing {filepath}: {e}", file=sys.stderr)
        return []


def main():
    src_dir = Path('src/netsleuth')
    total_missing = 0
    
    for py_file in src_dir.glob('*.py'):
        missing = check_file(py_file)
        if missing:
            print(f"\n{py_file.relative_to(Path.cwd())}:")
            for lineno, funcname in missing:
                print(f"  Line {lineno}: {funcname}()")
                total_missing += 1
    
    print(f"\n{'='*50}")
    print(f"Total functions missing docstrings: {total_missing}")
    return 0 if total_missing == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
