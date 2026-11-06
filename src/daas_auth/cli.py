"""
The service's own commands: `uv run daas-auth --help`.
"""

from datetime import UTC, datetime
from typing import Annotated

import typer
from sqlalchemy.orm import Session

from daas_auth.config import load_import_settings, load_settings
from daas_auth.db import make_engine
from daas_auth.domain.tokens import purge_tokens
from daas_auth.php_import import ImportRefused, import_php
from daas_auth.seed import SeedRefused, seed_database

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


@app.command("seed")
def seed(
    email: Annotated[str, typer.Option(help="The admin's email.")],
    name: Annotated[str, typer.Option(help="The admin's name.")] = "Administrator",
) -> None:
    """Create the first admin and test-client. The database must be at head and empty."""
    # Asked for, not an option: an option would end up in the shell history.
    password: str = typer.prompt(
        "Admin password", hide_input=True, confirmation_prompt=True
    )
    engine = make_engine(load_settings().database_url)
    try:
        with Session(engine) as session:
            admin_id = seed_database(session, email=email, name=name, password=password)
    except SeedRefused as refused:
        typer.echo(f"Refused, nothing written: {refused}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"admin {admin_id} and test-client created")


@app.command("purge-tokens")
def purge_tokens_command() -> None:
    """Delete the token rows of finished logins. Safe to run at any time."""
    engine = make_engine(load_settings().database_url)
    with Session(engine) as session:
        count = purge_tokens(session, datetime.now(UTC).replace(tzinfo=None))
        session.commit()
    typer.echo(f"{count} token rows deleted")
