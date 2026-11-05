from collections.abc import Callable
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.api.dependencies import now
from daas_auth.domain.activity import Action, record
from daas_auth.domain.passwords import hash_password
from daas_auth.domain.throttle import MAX_PER_ACCOUNT, MAX_PER_ADDRESS, WINDOW
from daas_auth.models import ActivityLog, OAuth2Token

URL = "/oauth2/user/token"
NOW = datetime(2026, 11, 4, 12, 0)
ADDRESS = "testclient"  # the address TestClient connects from
Guesses = Callable[..., None]


@pytest.fixture
def guesses(app: FastAPI) -> Guesses:
    """guesses(count, ...) adds what count failed logins leave in activity_log."""

    def add(
        count: int,
        *,
        email: str = "nobody@x.de",
        address: str = "10.0.0.1",
        reason: str = "wrong_password",
        at: datetime = NOW,
    ) -> None:
        with Session(app.state.engine) as session:
            for _ in range(count):
                record(
                    session,
                    Action.LOGIN,
                    ok=False,
                    now=at,
                    reason=reason,
                    actor_email=email,
                    source_ip=address,
                )
            session.commit()

    app.dependency_overrides[now] = lambda: NOW
    return add


def throttled_rows(app: FastAPI) -> int:
    with Session(app.state.engine) as session:
        logged = select(ActivityLog).where(ActivityLog.reason == "throttled")
        return len(session.scalars(logged).all())


def test_one_guess_below_the_limit_can_still_log_in(
    client: TestClient, admin_login: dict[str, str], guesses: Guesses
) -> None:
    guesses(MAX_PER_ADDRESS - 1, address=ADDRESS)
    assert client.post(URL, data=admin_login).status_code == 200


def test_at_the_address_limit_even_the_right_password_is_refused(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    guesses: Guesses,
) -> None:
    guesses(MAX_PER_ADDRESS, address=ADDRESS)
    response = client.post(URL, data=admin_login)
    assert response.status_code == 429
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"] == "Too many failed logins. Try again later."
    with Session(app.state.engine) as session:
        assert session.scalars(select(OAuth2Token)).first() is None
    assert throttled_rows(app) == 1


def test_retry_after_is_when_the_oldest_guess_leaves_the_window(
    client: TestClient, admin_login: dict[str, str], guesses: Guesses
) -> None:
    guesses(1, address=ADDRESS, at=NOW - timedelta(minutes=10))
    guesses(MAX_PER_ADDRESS - 1, address=ADDRESS)
    response = client.post(URL, data=admin_login)
    assert response.headers["retry-after"] == str(5 * 60)


def test_at_the_account_limit_every_address_is_refused(
    client: TestClient,
    admin_login: dict[str, str],
    add_user: Callable[..., int],
    guesses: Guesses,
) -> None:
    add_user("anna@x.de", hash_password("anna-pw-1"))
    guesses(MAX_PER_ACCOUNT, email=admin_login["username"])
    assert client.post(URL, data=admin_login).status_code == 429
    # the spelling of the email does not get around it
    upper = admin_login | {"username": admin_login["username"].upper()}
    assert client.post(URL, data=upper).status_code == 429
    # another account from the same address is not affected
    anna = admin_login | {
        "username": "anna@x.de",
        "password": "anna-pw-1",
        "scope": "user",
    }
    assert client.post(URL, data=anna).status_code == 200


def test_an_account_that_does_not_exist_is_refused_the_same_way(
    client: TestClient, admin_login: dict[str, str], guesses: Guesses
) -> None:
    guesses(MAX_PER_ACCOUNT, email="nobody@x.de", reason="unknown_user")
    form = admin_login | {"username": "nobody@x.de"}
    assert client.post(URL, data=form).status_code == 429


def test_guesses_older_than_the_window_do_not_count(
    client: TestClient, admin_login: dict[str, str], guesses: Guesses
) -> None:
    guesses(MAX_PER_ADDRESS, address=ADDRESS, at=NOW - WINDOW)
    assert client.post(URL, data=admin_login).status_code == 200


@pytest.mark.parametrize("reason", ["disabled", "invalid_scope", "throttled"])
def test_other_refusals_are_no_guesses(
    client: TestClient, admin_login: dict[str, str], guesses: Guesses, reason: str
) -> None:
    guesses(MAX_PER_ADDRESS, address=ADDRESS, reason=reason)
    assert client.post(URL, data=admin_login).status_code == 200


def test_a_wrong_password_counts_and_a_refresh_is_not_limited(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    guesses: Guesses,
) -> None:
    refresh_token = client.post(URL, data=admin_login).json()["refresh_token"]
    wrong = admin_login | {"password": "not-the-password"}
    guesses(MAX_PER_ADDRESS - 1, address=ADDRESS)
    assert client.post(URL, data=wrong).status_code == 400
    assert client.post(URL, data=admin_login).status_code == 429
    form = {
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "refresh_token": refresh_token,
    }
    assert client.post(URL, data=form).status_code == 200
