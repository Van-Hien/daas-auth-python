from collections.abc import Callable
from datetime import datetime, timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from daas_auth.api.auth import now
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


def test_a_missing_or_forged_token_is_refused(client: TestClient) -> None:
    for headers, hint in (
        ({}, 'Missing "Authorization" header'),
        (bearer("nonsense"), "Access token could not be verified"),
    ):
        response = client.get("/oauth2/user/session", headers=headers)
        assert response.status_code == 401
        assert response.json() == {
            "error": "access_denied",
            "error_description": "The resource owner or authorization server denied"
            " the request.",
            "hint": hint,
            "message": "The resource owner or authorization server denied the request.",
        }


def test_an_expired_token_is_refused(app: FastAPI, client: TestClient) -> None:
    token = token_for(app, "admin@x.de", ["admin"])
    at(app, LOGIN_TIME + timedelta(hours=2) - timedelta(seconds=1))  # last second
    assert client.get("/oauth2/user/session", headers=bearer(token)).status_code == 200
    at(app, LOGIN_TIME + timedelta(hours=2))  # exactly the lifetime: expired
    response = client.get("/oauth2/user/session", headers=bearer(token))
    assert response.status_code == 401
    assert response.json()["hint"] == "Access token could not be verified"


def test_a_revoked_token_or_disabled_user_is_refused(
    app: FastAPI, client: TestClient
) -> None:
    at(app, LOGIN_TIME + timedelta(hours=1))
    revoked = token_for(app, "admin@x.de", ["admin"])
    with Session(app.state.engine) as session:
        session.execute(update(OAuth2Token).values(revoked_at=LOGIN_TIME))
        session.commit()
    response = client.get("/oauth2/user/session", headers=bearer(revoked))
    assert response.json()["hint"] == "Access token has been revoked"

    valid = token_for(app, "admin@x.de", ["admin"])
    with Session(app.state.engine) as session:
        session.execute(update(User).values(enabled=False))
        session.commit()
    response = client.get("/oauth2/user/session", headers=bearer(valid))
    assert (response.status_code, response.json()["hint"]) == (401, "User disabled")


def test_a_route_refuses_a_token_without_its_scope(
    app: FastAPI, client: TestClient, add_user: Callable[..., int]
) -> None:
    at(app, LOGIN_TIME + timedelta(hours=1))
    admin = bearer(token_for(app, "admin@x.de", ["admin"]))
    assert client.get("/ping/admin", headers=admin).status_code == 200
    response = client.get("/ping/user", headers=admin)
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_permissions"
    assert response.json()["hint"] == (
        'Invalid scopes, need one of "user" but the token only contains "admin"'
    )
