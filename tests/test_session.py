from collections.abc import Callable
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from daas_auth.api.dependencies import now
from daas_auth.domain.tokens import SESSION_MAX, expiry, new_token, save_pair
from daas_auth.models import OAuth2Token, User

LOGIN_TIME = datetime(2026, 11, 2, 9, 0)


def token_for(app: FastAPI, email: str, scopes: list[str]) -> str:
    """An access token as a login would issue it, without the login route."""
    access_token = new_token()
    with Session(app.state.engine) as session:
        user_id = session.scalars(select(User.id).where(User.email == email)).one()
        save_pair(
            session,
            access_token=access_token,
            refresh_token=new_token(),
            user_id=user_id,
            client_id="test-client",
            scopes=scopes,
            family_id=None,
            now=LOGIN_TIME,
            expires=expiry(LOGIN_TIME, LOGIN_TIME + SESSION_MAX),
        )
        session.commit()
    return access_token


def at(app: FastAPI, moment: datetime) -> None:
    app.dependency_overrides[now] = lambda: moment


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def refusal(response: Response) -> tuple[int, str, dict[str, str]]:
    """Status, WWW-Authenticate and body of a refused request."""
    return (
        response.status_code,
        response.headers["WWW-Authenticate"],
        response.json(),
    )


def test_session_names_the_caller(app: FastAPI, client: TestClient) -> None:
    at(app, LOGIN_TIME + timedelta(hours=1))
    response = client.get(
        "/oauth2/user/session", headers=bearer(token_for(app, "admin@x.de", ["admin"]))
    )
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "user_id": body["user_id"],
        "email": "admin@x.de",
        "name": "Admin",
        "scopes": ["admin"],
    }
    assert isinstance(body["user_id"], int)


def test_a_request_without_a_bearer_token_gets_a_bare_challenge(
    client: TestClient,
) -> None:
    # No token, or another scheme: the client did not know a token was needed.
    for headers in ({}, {"Authorization": "Basic YTpi"}, {"Authorization": "abc"}):
        response = client.get("/oauth2/user/session", headers=headers)
        assert refusal(response) == (401, "Bearer", {})


def test_a_forged_token_is_refused(client: TestClient) -> None:
    response = client.get("/oauth2/user/session", headers=bearer("nonsense"))
    description = "The access token is unknown."
    assert refusal(response) == (
        401,
        f'Bearer error="invalid_token", error_description="{description}"',
        {"error": "invalid_token", "error_description": description},
    )


def test_an_expired_token_is_refused(app: FastAPI, client: TestClient) -> None:
    token = token_for(app, "admin@x.de", ["admin"])
    at(app, LOGIN_TIME + timedelta(hours=2) - timedelta(seconds=1))  # last second
    assert client.get("/oauth2/user/session", headers=bearer(token)).status_code == 200
    at(app, LOGIN_TIME + timedelta(hours=2))  # exactly the lifetime: expired
    response = client.get("/oauth2/user/session", headers=bearer(token))
    assert response.status_code == 401
    assert response.json()["error_description"] == "The access token has expired."


def test_a_revoked_token_or_disabled_user_is_refused(
    app: FastAPI, client: TestClient
) -> None:
    at(app, LOGIN_TIME + timedelta(hours=1))
    revoked = token_for(app, "admin@x.de", ["admin"])
    with Session(app.state.engine) as session:
        session.execute(update(OAuth2Token).values(revoked_at=LOGIN_TIME))
        session.commit()
    response = client.get("/oauth2/user/session", headers=bearer(revoked))
    assert response.json()["error_description"] == "The access token has been revoked."

    valid = token_for(app, "admin@x.de", ["admin"])
    with Session(app.state.engine) as session:
        session.execute(update(User).values(enabled=False))
        session.commit()
    response = client.get("/oauth2/user/session", headers=bearer(valid))
    assert (response.status_code, response.json()["error_description"]) == (
        401,
        "The account is disabled.",
    )


def test_a_route_refuses_a_token_without_its_scope(
    app: FastAPI, client: TestClient, add_user: Callable[..., int]
) -> None:
    at(app, LOGIN_TIME + timedelta(hours=1))
    admin = bearer(token_for(app, "admin@x.de", ["admin"]))
    assert client.get("/ping/admin", headers=admin).status_code == 200
    response = client.get("/ping/user", headers=admin)
    description = "This route needs the scope 'user'."
    challenge = (
        f'Bearer error="insufficient_scope", error_description="{description}",'
        ' scope="user"'
    )
    body = {"error": "insufficient_scope", "error_description": description}
    assert refusal(response) == (403, challenge, body | {"scope": "user"})


def test_a_refused_bearer_is_logged_without_the_token(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    token = "not-a-real-token"
    headers = {"Authorization": f"Bearer {token}"}
    with caplog.at_level("WARNING", logger="daas_auth.domain.bearer"):
        assert client.get("/oauth2/user/session", headers=headers).status_code == 401
    assert "bearer refused: unknown" in caplog.text
    assert token not in caplog.text
