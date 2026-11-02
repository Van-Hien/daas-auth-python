from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog

Login = Callable[..., dict[str, str]]


def test_no_registration_code_matches(client: TestClient) -> None:
    # The suite's two row-4 cases: too short is a schema error, a wrong code is empty.
    short = client.post(
        "/user/validate_email", json={"email": "a@x.de", "registration_code": "short"}
    )
    assert (short.status_code, short.headers["content-type"]) == (
        400,
        "application/problem+json",
    )
    wrong = client.post(
        "/user/validate_email",
        json={"email": "a@x.de", "registration_code": "AAAAAAAAAAA"},
    )
    assert (wrong.status_code, wrong.content) == (400, b"")


def test_an_application_request_is_recorded(
    app: FastAPI, client: TestClient, login: Login, add_user: Callable[..., int]
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    user = login("anna@x.de", "anna-pw-1", "user")
    response = client.post("/user/request-application/Firefox/deu", headers=user)
    assert (response.status_code, response.content) == (200, b"")
    with Session(app.state.engine) as session:
        row = session.scalars(
            select(ActivityLog).order_by(ActivityLog.id.desc())
        ).first()
        assert row is not None
        assert (row.action, row.created_by, row.details) == (
            "application_request",
            anna,
            "Firefox (deu)",
        )


def test_refusals_of_the_application_request(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    # The suite's row 5: an admin token on the user dashboard's route.
    response = client.post("/user/request-application/Firefox/eng", headers=admin)
    assert (response.status_code, response.json()["error"]) == (
        403,
        "insufficient_scope",
    )
    add_user("anna@x.de", hash_password("anna-pw-1"))
    user = login("anna@x.de", "anna-pw-1", "user")
    bad = client.post("/user/request-application/Firefox/english", headers=user)
    assert bad.status_code == 400
