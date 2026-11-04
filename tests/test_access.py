from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import (
    Desktop,
    DesktopGroup,
    DesktopGroupUserGroup,
    DesktopToDesktopGroup,
    UserGroup,
    UserToUserGroup,
)

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]
NOW = datetime(2026, 11, 3)
STAMP = {"created_at": NOW, "updated_at": NOW}


def chain(app: FastAPI, user_id: int) -> None:
    """
    user -> user group 2 -> desktop group 5 -> desktop 9 (templateWin10).
    Every id differs, so a check that compares ids across tables cannot pass (R-3).
    Also user group 5 and desktop group 2 exist, unlinked: PHP's comparison of a
    user-group id with a desktop-group id would find those.
    """
    with Session(app.state.engine) as session:
        session.add_all(
            [
                UserGroup(id=2, description="u2", **STAMP),
                UserGroup(id=5, description="u5", **STAMP),
                DesktopGroup(id=5, description="d5", **STAMP),
                DesktopGroup(id=2, description="d2", **STAMP),
                Desktop(
                    id=9, description="w", quart_object_id="templateWin10", **STAMP
                ),
                Desktop(
                    id=8, description="o", quart_object_id="templateDeb12", **STAMP
                ),
            ]
        )
        session.flush()  # no relationship orders the inserts, so the rows first
        session.add_all(
            [
                UserToUserGroup(user_id=user_id, user_group_id=2, **STAMP),
                DesktopGroupUserGroup(desktop_group_id=5, user_group_id=2, **STAMP),
                DesktopToDesktopGroup(desktop_id=9, desktop_group_id=5, **STAMP),
                # desktop 8 is in desktop group 2, which no user group may use
                DesktopToDesktopGroup(desktop_id=8, desktop_group_id=2, **STAMP),
            ]
        )
        session.commit()


def test_a_user_may_use_a_desktop_through_the_group_chain(
    app: FastAPI, client: TestClient, login: Login, add_user: Callable[..., int]
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    chain(app, anna)
    user = login("anna@x.de", "anna-pw-1", "user")

    allowed = client.get("/oauth2/user/desktops/templateWin10", headers=user)
    assert (allowed.status_code, allowed.json()["id"]) == (200, 9)
    denied = client.get("/oauth2/user/desktops/templateDeb12", headers=user)
    assert (denied.status_code, denied.headers["content-type"]) == (403, PROBLEM)
    listed = client.get("/oauth2/user/desktops", headers=user).json()
    assert listed == [
        {
            "id": 9,
            "description": "w",
            "name": None,
            "quart_object_id": "templateWin10",
        }
    ]


def test_removing_the_link_counts_at_the_very_next_check(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    chain(app, anna)
    user = login("anna@x.de", "anna-pw-1", "user")
    path = "/oauth2/user/desktops/templateWin10"
    assert client.get(path, headers=user).status_code == 200

    client.delete("/desktop_group/5/user_group/2", headers=admin)
    # The same token, no new login (R-3).
    assert client.get(path, headers=user).status_code == 403
    assert client.get("/oauth2/user/desktops", headers=user).json() == []


def test_an_admin_may_use_every_desktop(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    chain(app, add_user("anna@x.de", hash_password("anna-pw-1")))
    listed = client.get("/oauth2/user/desktops", headers=admin).json()
    assert [desktop["id"] for desktop in listed] == [8, 9]
    check = client.get("/oauth2/user/desktops/templateDeb12", headers=admin)
    assert check.status_code == 200


def test_an_object_no_desktop_is_is_404(
    client: TestClient, admin: dict[str, str]
) -> None:
    response = client.get("/oauth2/user/desktops/nothing-here", headers=admin)
    assert (response.status_code, response.headers["content-type"]) == (404, PROBLEM)
