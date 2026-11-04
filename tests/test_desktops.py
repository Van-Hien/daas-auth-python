from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog, DesktopGroup

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]


def add_desktop_groups(app: FastAPI, *ids: int) -> None:
    now = datetime(2026, 11, 3)
    with Session(app.state.engine) as session:
        for group_id in ids:
            session.add(
                DesktopGroup(
                    id=group_id,
                    description=f"dg{group_id}",
                    created_at=now,
                    updated_at=now,
                )
            )
        session.commit()


def test_an_admin_creates_a_desktop_in_two_groups(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    add_desktop_groups(app, 101, 102)
    body = {
        "description": "Windows 10",
        "groups": [102, 101, 102],
        "quart_object_id": "templateWin10",
    }
    # The suite's row 17 with groups as ids: stored, unlike PHP (R-3).
    response = client.post("/desktop", json=body, headers=admin)
    assert response.status_code == 200
    desktop = response.json()
    assert desktop == {
        "id": desktop["id"],
        "description": "Windows 10",
        "groups": [101, 102],
        "name": None,
        "quart_object_id": "templateWin10",
    }
    # Rows 16 and 18.
    assert client.get(f"/desktop/{desktop['id']}", headers=admin).json() == desktop
    assert client.get("/desktops", headers=admin).json() == [desktop]
    with Session(app.state.engine) as session:
        row = session.scalars(
            select(ActivityLog).order_by(ActivityLog.id.desc())
        ).first()
        assert row is not None
        assert (row.action, row.target_id) == ("desktop_create", desktop["id"])


def test_refusals_of_post_desktop(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    # The first is the dashboard's body: groups as objects, not ids.
    bodies: list[tuple[dict[str, object], int]] = [
        ({"description": "x", "groups": [{"description": "x"}]}, 400),  # Bad Request
        ({"description": "x", "groups": [999]}, 422),  # Unprocessable Content
        ({"groups": []}, 400),  # Bad Request
    ]
    for body, status in bodies:
        response = client.post("/desktop", json=body, headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            status,
            PROBLEM,
        ), body

    one = {"description": "x", "quart_object_id": "templateWin10"}
    assert client.post("/desktop", json=one, headers=admin).status_code == 200
    taken = client.post("/desktop", json=one, headers=admin)
    assert (taken.status_code, taken.headers["content-type"]) == (409, PROBLEM)
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    assert (
        client.post("/desktop", json={"description": "x"}, headers=user).status_code
        == 403
    )
    assert client.get("/desktops", headers=user).status_code == 403


def test_patch_links_a_desktop_to_quart_and_moves_its_groups(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    add_desktop_groups(app, 101, 102)
    created = client.post(
        "/desktop", json={"description": "d", "groups": [101]}, headers=admin
    ).json()
    response = client.patch(
        f"/desktop/{created['id']}",
        json={"quart_object_id": "templateDeb12", "name": "Debian", "groups": [102]},
        headers=admin,
    )
    assert response.status_code == 200
    assert response.json() | {"id": 0} == {
        "id": 0,
        "description": "d",
        "groups": [102],
        "name": "Debian",
        "quart_object_id": "templateDeb12",
    }


def test_refusals_of_get_and_patch_desktop(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    for response in (
        client.get("/desktop/999", headers=admin),
        client.patch("/desktop/999", json={"name": "x"}, headers=admin),
    ):
        assert (response.status_code, response.headers["content-type"]) == (
            404,
            PROBLEM,
        )
    desktop = client.post("/desktop", json={"description": "x"}, headers=admin).json()
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    assert client.get(f"/desktop/{desktop['id']}", headers=user).status_code == 403
    denied = client.patch(f"/desktop/{desktop['id']}", json={}, headers=user)
    assert denied.status_code == 403


def test_deleting_a_desktop_keeps_its_groups(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    add_desktop_groups(app, 101)
    desktop = client.post(
        "/desktop", json={"description": "x", "groups": [101]}, headers=admin
    ).json()
    response = client.delete(f"/desktop/{desktop['id']}", headers=admin)
    assert (response.status_code, response.json()) == (200, "Desktop deleted")
    assert client.get("/desktops", headers=admin).json() == []
    with Session(app.state.engine) as session:
        assert session.get(DesktopGroup, 101) is not None

    missing = client.delete(f"/desktop/{desktop['id']}", headers=admin)
    assert (missing.status_code, missing.headers["content-type"]) == (404, PROBLEM)
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    assert client.delete("/desktop/1", headers=user).status_code == 403
