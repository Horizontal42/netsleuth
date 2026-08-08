from __future__ import annotations

import typer

from netcheck import __version__

app = typer.Typer(add_completion=False, help="Deep network diagnostics.")


@app.command()
def run() -> None:
    typer.echo(f"netcheck {__version__}")


def main() -> None:
    app()
