"""
The service's own commands: `uv run daas-auth --help`.
"""

import typer

from daas_auth.config import load_import_settings, load_settings
from daas_auth.db import make_engine
from daas_auth.php_import import ImportRefused, import_php

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """
    DESIGN DaaS auth service.
    """


@app.command("import-php")
def import_php_command() -> None:
    """
    Copy PHP's rows into the database. DB must be at revision 0001 and empty.
    """
    source_engine = make_engine(load_import_settings().url())
    target_engine = make_engine(load_settings().database_url)
    try:
        with source_engine.connect() as source, target_engine.connect() as target:
            copied = import_php(source, target)
    except ImportRefused as refused:
        typer.echo(f"Refused, nothing written: {refused}", err=True)
        raise typer.Exit(1) from None
    for name, count in copied.items():
        typer.echo(f"{count:>4}  {name}")
