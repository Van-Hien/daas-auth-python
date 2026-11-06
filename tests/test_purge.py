from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from daas_auth.api.dependencies import now
from daas_auth.cli import app as cli
from daas_auth.domain.tokens import REFRESH_TTL, SESSION_MAX, purge_tokens
from daas_auth.models import ActivityLog, OAuth2Token

URL = "/oauth2/user/token"
LOGIN_TIME = datetime(2026, 1, 4, 9, 0)  # long past: the command uses the real clock
# The moment the login's only row reaches the purge's limit.
LAST_KEPT = LOGIN_TIME + REFRESH_TTL + SESSION_MAX


def token_rows(app: FastAPI) -> int:
    with Session(app.state.engine) as session:
        return len(session.scalars(select(OAuth2Token)).all())


@pytest.fixture
def one_login(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> dict[str, str]:
    app.dependency_overrides[now] = lambda: LOGIN_TIME
    pair: dict[str, str] = client.post(URL, data=admin_login).json()
    return pair


@pytest.mark.usefixtures("one_login")
def test_a_row_stays_until_no_relative_can_be_alive(app: FastAPI) -> None:
    with Session(app.state.engine) as session:
        assert purge_tokens(session, LAST_KEPT) == 0
        session.commit()
    assert token_rows(app) == 1


@pytest.mark.usefixtures("one_login")
def test_then_it_is_deleted_and_the_purge_is_logged(app: FastAPI) -> None:
    with Session(app.state.engine) as session:
        assert purge_tokens(session, LAST_KEPT + timedelta(seconds=1)) == 1
        session.commit()
        logged = session.scalars(
            select(ActivityLog).where(ActivityLog.action == "token_purge")
        ).one()
    assert (logged.result, logged.details) == ("ok", "1 rows deleted")
    assert token_rows(app) == 0


def test_a_used_token_is_still_recognised_when_it_has_expired(
    app: FastAPI,
    client: TestClient,
    one_login: dict[str, str],
) -> None:
    form = {
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "refresh_token": one_login["refresh_token"],
    }
    app.dependency_overrides[now] = lambda: LOGIN_TIME + timedelta(hours=1)
    assert client.post(URL, data=form).status_code == 200
    with Session(app.state.engine) as session:
        purge_tokens(session, LOGIN_TIME + timedelta(hours=9))
        session.commit()
    assert token_rows(app) == 2


@pytest.mark.usefixtures("one_login")
def test_the_command_says_how_many(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "DAAS_AUTH_DATABASE_URL", app.state.engine.url.render_as_string(False)
    )
    result = CliRunner().invoke(cli, ["purge-tokens"])
    assert (result.exit_code, result.output) == (0, "1 token rows deleted\n")
    assert token_rows(app) == 0
